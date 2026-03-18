//! AWS Bedrock AI model integration.
//!
//! Provides:
//! - `BedrockClient` for synchronous model invocations (embeddings, LLM calls)
//! - Helpers for consuming Bedrock's `ConverseStream` API and converting
//!   events to Server-Sent Events (SSE) for web clients.
//! - `ConversationBuilder` for building multi-turn conversations with tool support
//! - `ToolCallHandler` for automated tool-call loops
//!
//! # Event Types (for streaming)
//!
//! - `content` - Text chunks from the model
//! - `toolUse` - Tool/function call requests
//! - `usage` - Token usage metadata
//! - `done` - Stream completion signal
//! - `error` - Error messages

use anyhow::{Context, Result};
use aws_sdk_bedrockruntime::Client;
use aws_sdk_bedrockruntime::primitives::event_stream::EventReceiver;
use aws_sdk_bedrockruntime::types::error::ConverseStreamOutputError;
use aws_sdk_bedrockruntime::types::{
    ContentBlock, ConversationRole, ConverseStreamOutput, InferenceConfiguration, Message,
    SystemContentBlock, Tool, ToolConfiguration, ToolInputSchema, ToolResultBlock,
    ToolResultContentBlock, ToolResultStatus, ToolSpecification, ToolUseBlock, ToolUseBlockStart,
};
use aws_smithy_types::Document;
use serde::Deserialize;
use serde_json::json;
use std::future::Future;
use std::pin::Pin;
use warp::sse::Event;

/// Convert serde_json::Value to aws_smithy_types::Document.
fn json_value_to_document(value: serde_json::Value) -> Document {
    match value {
        serde_json::Value::Null => Document::Null,
        serde_json::Value::Bool(b) => Document::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Document::Number(aws_smithy_types::Number::PosInt(i as u64))
            } else if let Some(f) = n.as_f64() {
                Document::Number(aws_smithy_types::Number::Float(f))
            } else {
                Document::Null
            }
        }
        serde_json::Value::String(s) => Document::String(s),
        serde_json::Value::Array(arr) => {
            Document::Array(arr.into_iter().map(json_value_to_document).collect())
        }
        serde_json::Value::Object(map) => Document::Object(
            map.into_iter()
                .map(|(k, v)| (k, json_value_to_document(v)))
                .collect(),
        ),
    }
}

/// Bedrock client for synchronous model invocations.
pub struct BedrockClient {
    client: Client,
}

impl BedrockClient {
    /// Create a new Bedrock client from AWS config.
    pub async fn from_env() -> Result<Self> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&config);
        Ok(Self { client })
    }

    /// Generate text embedding using Amazon Titan Embed Text v2.
    ///
    /// Returns a 1024-dimensional normalized embedding vector.
    /// Model ID: `amazon.titan-embed-text-v2:0`
    pub async fn embed_text(&self, text: &str) -> Result<Vec<f32>> {
        self.embed_text_with_model(text, "amazon.titan-embed-text-v2:0")
            .await
    }

    /// Generate text embedding using a specific embedding model.
    ///
    /// Returns a 1024-dimensional normalized embedding vector.
    /// Use this for non-Titan models or custom endpoints.
    pub async fn embed_text_with_model(&self, text: &str, model_id: &str) -> Result<Vec<f32>> {
        let body = json!({
            "inputText": text,
            "dimensions": 1024,
            "normalize": true
        });

        let response = self
            .client
            .invoke_model()
            .model_id(model_id)
            .content_type("application/json")
            .body(serde_json::to_vec(&body)?.into())
            .send()
            .await
            .context("Failed to invoke embedding model")?;

        let response_body: TitanEmbedResponse = serde_json::from_slice(response.body().as_ref())
            .context("Failed to parse embedding response")?;

        Ok(response_body.embedding)
    }

    /// Invoke Claude with a simple text prompt.
    ///
    /// Returns the model's text response.
    pub async fn invoke_claude(
        &self,
        model_id: &str,
        prompt: &str,
        max_tokens: i32,
    ) -> Result<String> {
        let body = json!({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        });

        let response = self
            .client
            .invoke_model()
            .model_id(model_id)
            .content_type("application/json")
            .body(serde_json::to_vec(&body)?.into())
            .send()
            .await
            .context("Failed to invoke model")?;

        let response_body: ClaudeResponse = serde_json::from_slice(response.body().as_ref())
            .context("Failed to parse model response")?;

        Ok(response_body
            .content
            .first()
            .and_then(|c| c.text.as_ref())
            .map(|s| s.trim().to_string())
            .unwrap_or_default())
    }
}

/// Titan embedding response structure.
#[derive(Deserialize)]
struct TitanEmbedResponse {
    embedding: Vec<f32>,
}

/// Claude response structure.
#[derive(Deserialize)]
struct ClaudeResponse {
    content: Vec<ClaudeContent>,
}

#[derive(Deserialize)]
struct ClaudeContent {
    text: Option<String>,
}

/// Events emitted by Bedrock model responses.
pub enum ModelEvent {
    /// A text chunk from the model's response.
    Text(String),
    /// A tool/function call request from the model.
    ToolUse(ToolUse),
    /// Notification that a tool is about to be executed (only in tool-call loops).
    ToolCallStarted {
        /// Tool use ID for correlating with completion.
        id: String,
        /// Tool name being invoked.
        name: String,
        /// Tool input as JSON string.
        input: String,
    },
    /// Notification that a tool execution completed (only in tool-call loops).
    ToolCallCompleted {
        /// Tool use ID for correlating with start.
        id: String,
        /// Tool name that was invoked.
        name: String,
        /// Tool result.
        result: String,
    },
    /// Token usage metadata at the end of the response.
    Metadata {
        /// Number of tokens in the input prompt.
        input_tokens: i32,
        /// Number of tokens in the model's response.
        output_tokens: i32,
    },
    /// Stream completion signal.
    Done,
}

/// Tool/function call request from the model.
#[derive(Default, Debug, Clone)]
pub struct ToolUse {
    /// Unique ID for correlating tool results.
    pub id: String,
    /// Tool name to invoke.
    pub name: String,
    /// JSON-encoded tool arguments.
    pub input: String,
}

impl From<ModelEvent> for Event {
    fn from(val: ModelEvent) -> Self {
        match &val {
            ModelEvent::Text(chunk) => Event::default()
                .event("content")
                .json_data(json!({ "text": chunk }))
                .unwrap_or_else(|_| sse_error("bad json")),
            ModelEvent::ToolUse(tool_use) => Event::default()
                .event("toolUse")
                .json_data(
                    json!({ "id": tool_use.id, "name": tool_use.name, "input": tool_use.input }),
                )
                .unwrap_or_else(|_| sse_error("bad json")),
            ModelEvent::ToolCallStarted { id, name, input: _ } => Event::default()
                .event("toolCallStarted")
                .json_data(json!({ "id": id, "name": name }))
                .unwrap_or_else(|_| sse_error("bad json")),
            ModelEvent::ToolCallCompleted {
                id,
                name,
                result: _,
            } => Event::default()
                .event("toolCallCompleted")
                .json_data(json!({ "id": id, "name": name }))
                .unwrap_or_else(|_| sse_error("bad json")),
            ModelEvent::Metadata {
                input_tokens,
                output_tokens,
            } => Event::default()
                .event("usage")
                .json_data(json!({ "inputTokens": input_tokens, "outputTokens": output_tokens }))
                .unwrap_or_else(|_| sse_error("bad json")),
            ModelEvent::Done => Event::default().event("done").data("true"),
        }
    }
}

/// Creates an SSE error event.
pub fn sse_error(msg: impl Into<String>) -> Event {
    Event::default().event("error").data(msg.into())
}

type Receiver = EventReceiver<ConverseStreamOutput, ConverseStreamOutputError>;

/// Reads the next event from a Bedrock ConverseStream.
///
/// Loops internally to skip non-content events, returning only meaningful events.
pub async fn read_next_event(receiver: &mut Receiver) -> Result<ModelEvent, String> {
    loop {
        match receiver.recv().await {
            Ok(Some(output)) => match output {
                ConverseStreamOutput::ContentBlockDelta(delta) => {
                    if let Some(delta) = delta.delta()
                        && let Ok(text) = delta.as_text()
                    {
                        return Ok(ModelEvent::Text(text.to_owned()));
                    }
                }
                ConverseStreamOutput::ContentBlockStart(block_start) => {
                    if let Some(Ok(tool_use_start)) =
                        block_start.start().map(|start| start.as_tool_use())
                    {
                        return Ok(ModelEvent::ToolUse(
                            read_tool_use(tool_use_start, receiver).await?,
                        ));
                    }
                }
                ConverseStreamOutput::Metadata(metadata) => {
                    if let Some(usage) = metadata.usage {
                        return Ok(ModelEvent::Metadata {
                            input_tokens: usage.input_tokens,
                            output_tokens: usage.output_tokens,
                        });
                    }
                }
                _ => {}
            },
            Ok(None) => return Ok(ModelEvent::Done),
            Err(e) => return Err(format!("Stream receive error: {:#?}", e)),
        }
    }
}

async fn read_tool_use(
    tool_use: &ToolUseBlockStart,
    receiver: &mut Receiver,
) -> Result<ToolUse, String> {
    let mut input = String::new();
    loop {
        match receiver.recv().await {
            Ok(Some(output)) => match output {
                ConverseStreamOutput::ContentBlockDelta(delta) => {
                    if let Some(delta) = delta.delta()
                        && let Ok(text) = delta.as_tool_use()
                    {
                        input.push_str(text.input());
                    }
                }
                ConverseStreamOutput::ContentBlockStop(_)
                | ConverseStreamOutput::MessageStop(_) => {
                    return Ok(ToolUse {
                        id: tool_use.tool_use_id.to_owned(),
                        name: tool_use.name.to_owned(),
                        input,
                    });
                }
                _ => {}
            },
            Ok(None) => {
                return Ok(ToolUse {
                    id: tool_use.tool_use_id.to_owned(),
                    name: tool_use.name.to_owned(),
                    input,
                });
            }
            Err(e) => return Err(format!("JSON parse error: {:#?}", e)),
        }
    }
}

// ============================================================================
// Tool Support
// ============================================================================

/// Helper for creating tool definitions with JSON schemas.
pub struct ToolBuilder {
    name: String,
    description: String,
    schema: serde_json::Value,
}

impl ToolBuilder {
    /// Create a new tool builder.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }

    /// Add a required string parameter.
    #[expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "schema is initialized with known structure"
    )]
    pub fn with_string_param(mut self, name: &str, description: &str) -> Self {
        self.schema["properties"][name] = json!({
            "type": "string",
            "description": description
        });
        self.schema["required"]
            .as_array_mut()
            .unwrap()
            .push(json!(name));
        self
    }

    /// Add an optional string parameter.
    #[expect(
        clippy::indexing_slicing,
        reason = "schema is initialized with known structure"
    )]
    pub fn with_optional_string_param(mut self, name: &str, description: &str) -> Self {
        self.schema["properties"][name] = json!({
            "type": "string",
            "description": description
        });
        self
    }

    /// Add a required number parameter.
    #[expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "schema is initialized with known structure"
    )]
    pub fn with_number_param(mut self, name: &str, description: &str) -> Self {
        self.schema["properties"][name] = json!({
            "type": "number",
            "description": description
        });
        self.schema["required"]
            .as_array_mut()
            .unwrap()
            .push(json!(name));
        self
    }

    /// Build the tool.
    pub fn build(self) -> Result<Tool> {
        Ok(Tool::ToolSpec(
            ToolSpecification::builder()
                .name(self.name)
                .description(self.description)
                .input_schema(ToolInputSchema::Json(json_value_to_document(self.schema)))
                .build()
                .context("Failed to build tool specification")?,
        ))
    }
}

// ============================================================================
// Conversation Builder
// ============================================================================

/// Builder for multi-turn conversations with tool support.
pub struct ConversationBuilder {
    messages: Vec<Message>,
}

impl ConversationBuilder {
    /// Create a new conversation builder.
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    /// Add a user message.
    #[expect(clippy::expect_used, reason = "builder has all required fields")]
    pub fn user(mut self, text: impl Into<String>) -> Self {
        self.messages.push(
            Message::builder()
                .role(ConversationRole::User)
                .content(ContentBlock::Text(text.into()))
                .build()
                .expect("Failed to build user message"),
        );
        self
    }

    /// Add an assistant message.
    #[expect(clippy::expect_used, reason = "builder has all required fields")]
    pub fn assistant(mut self, text: impl Into<String>) -> Self {
        self.messages.push(
            Message::builder()
                .role(ConversationRole::Assistant)
                .content(ContentBlock::Text(text.into()))
                .build()
                .expect("Failed to build assistant message"),
        );
        self
    }

    /// Add a tool use (assistant's tool call).
    #[expect(clippy::expect_used, reason = "builders have all required fields")]
    pub fn tool_use(
        mut self,
        id: impl Into<String>,
        name: impl Into<String>,
        input: impl Into<String>,
    ) -> Self {
        let input_str = input.into();

        // Parse tool input as JSON. If empty or invalid, default to empty object
        // (Bedrock requires a JSON object, not a string)
        let doc = if input_str.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&input_str).unwrap_or_else(|_| {
                tracing::warn!(
                    "Failed to parse tool input as JSON in ConversationBuilder, using empty object"
                );
                serde_json::json!({})
            })
        };

        self.messages.push(
            Message::builder()
                .role(ConversationRole::Assistant)
                .content(ContentBlock::ToolUse(
                    ToolUseBlock::builder()
                        .tool_use_id(id.into())
                        .name(name.into())
                        .input(json_value_to_document(doc))
                        .build()
                        .expect("Failed to build tool use block"),
                ))
                .build()
                .expect("Failed to build tool use message"),
        );
        self
    }

    /// Add a tool result (user's response to tool call).
    #[expect(clippy::expect_used, reason = "builders have all required fields")]
    pub fn tool_result(
        mut self,
        tool_use_id: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        self.messages.push(
            Message::builder()
                .role(ConversationRole::User)
                .content(ContentBlock::ToolResult(
                    ToolResultBlock::builder()
                        .tool_use_id(tool_use_id.into())
                        .content(ToolResultContentBlock::Text(content.into()))
                        .status(ToolResultStatus::Success)
                        .build()
                        .expect("Failed to build tool result block"),
                ))
                .build()
                .expect("Failed to build tool result message"),
        );
        self
    }

    /// Build the message list.
    pub fn build(self) -> Vec<Message> {
        self.messages
    }
}

impl Default for ConversationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tool Call Handler
// ============================================================================

/// Callback function for handling tool calls.
///
/// Takes tool name and input JSON, returns result string.
pub type ToolCallback = Box<
    dyn Fn(String, String) -> Pin<Box<dyn Future<Output = Result<String>> + Send>> + Send + Sync,
>;

/// Configuration for tool-call-enabled conversations.
pub struct ToolCallConfig {
    /// Maximum number of tool-call rounds (default: 3).
    pub max_rounds: usize,
    /// Callback for handling tool invocations.
    pub callback: ToolCallback,
}

impl Default for ToolCallConfig {
    fn default() -> Self {
        Self {
            max_rounds: 3,
            callback: Box::new(|name, _input| {
                Box::pin(async move { Ok(format!("Tool '{}' not implemented", name)) })
            }),
        }
    }
}

/// Helper to conduct a conversation with automatic tool-call handling.
///
/// This function:
/// - Sends the initial request
/// - Listens for tool calls
/// - Invokes the callback with `ToolCallStarted`/`ToolCallCompleted` events
/// - Automatically continues the conversation with tool results
/// - Streams all text/metadata events to the caller
/// - Stops after `max_rounds` or when the model finishes without tool calls
#[expect(
    clippy::expect_used,
    reason = "AWS SDK builders have all required fields set"
)]
pub async fn converse_with_tools(
    client: Client,
    model_id: &str,
    system_prompt: Option<String>,
    messages: Vec<Message>,
    tools: Vec<Tool>,
    inference_config: Option<InferenceConfiguration>,
    config: ToolCallConfig,
) -> Result<impl futures::Stream<Item = Result<ModelEvent, String>>> {
    let mut conversation_history = messages;
    let mut round = 0;

    let stream = async_stream::stream! {
        loop {
            round += 1;
            if round > config.max_rounds {
                yield Err(format!("Tool call limit reached ({} rounds)", config.max_rounds));
                break;
            }

            // Build request
            let mut request = client
                .converse_stream()
                .model_id(model_id)
                .set_messages(Some(conversation_history.clone()));

            if let Some(ref prompt) = system_prompt {
                request = request.system(SystemContentBlock::Text(prompt.clone()));
            }

            if !tools.is_empty() {
                request = request.tool_config(
                    ToolConfiguration::builder()
                        .set_tools(Some(tools.clone()))
                        .build()
                        .expect("Failed to build tool configuration"),
                );
            }

            if let Some(ref cfg) = inference_config {
                request = request.inference_config(cfg.clone());
            }

            // Send request
            let mut response = match request.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    let error_msg = format!("Bedrock API error: {:#?}", e);
                    tracing::error!("{}", error_msg);
                    yield Err(error_msg);
                    break;
                }
            };

            // Process stream
            let mut tool_calls = Vec::new();

            loop {
                match read_next_event(&mut response.stream).await {
                    Ok(ModelEvent::Text(text)) => {
                        yield Ok(ModelEvent::Text(text));
                    }
                    Ok(ModelEvent::ToolUse(tool_use)) => {
                        tool_calls.push(tool_use);
                    }
                    Ok(ModelEvent::Metadata { input_tokens, output_tokens }) => {
                        yield Ok(ModelEvent::Metadata { input_tokens, output_tokens });
                    }
                    Ok(ModelEvent::ToolCallStarted { .. }) | Ok(ModelEvent::ToolCallCompleted { .. }) => {
                        // These events are only emitted by converse_with_tools, not by read_next_event
                    }
                    Ok(ModelEvent::Done) => break,
                    Err(e) => {
                        yield Err(e);
                        return;
                    }
                }
            }

            // If no tool calls, we're done
            if tool_calls.is_empty() {
                yield Ok(ModelEvent::Done);
                break;
            }

            // Add assistant's tool calls to history and notify about tool usage
            for tool_call in &tool_calls {
                // Emit raw ToolUse event with ID (for open-loop scenarios)
                yield Ok(ModelEvent::ToolUse(tool_call.clone()));

                // Parse tool input as JSON. If empty or invalid, default to empty object
                // (Bedrock requires a JSON object, not a string)
                let doc = if tool_call.input.trim().is_empty() {
                    serde_json::json!({})
                } else {
                    serde_json::from_str(&tool_call.input)
                        .unwrap_or_else(|e| {
                            tracing::warn!(
                                "Failed to parse tool input as JSON (tool={}, error={}), using empty object",
                                tool_call.name,
                                e
                            );
                            serde_json::json!({})
                        })
                };

                conversation_history.push(
                    Message::builder()
                        .role(ConversationRole::Assistant)
                        .content(ContentBlock::ToolUse(
                            ToolUseBlock::builder()
                                .tool_use_id(tool_call.id.clone())
                                .name(tool_call.name.clone())
                                .input(json_value_to_document(doc))
                                .build()
                                .expect("Failed to build tool use block"),
                        ))
                        .build()
                        .expect("Failed to build message"),
                );
            }

            // Execute tool calls and add results to history
            for tool_call in tool_calls {
                // Notify that tool execution is starting
                yield Ok(ModelEvent::ToolCallStarted {
                    id: tool_call.id.clone(),
                    name: tool_call.name.clone(),
                    input: tool_call.input.clone(),
                });

                let result = (config.callback)(tool_call.name.clone(), tool_call.input.clone()).await
                    .unwrap_or_else(|e| format!("Tool execution error: {}", e));

                // Notify that tool execution completed
                yield Ok(ModelEvent::ToolCallCompleted {
                    id: tool_call.id.clone(),
                    name: tool_call.name.clone(),
                    result: result.clone(),
                });

                conversation_history.push(
                    Message::builder()
                        .role(ConversationRole::User)
                        .content(ContentBlock::ToolResult(
                            ToolResultBlock::builder()
                                .tool_use_id(tool_call.id)
                                .content(ToolResultContentBlock::Text(result))
                                .status(ToolResultStatus::Success)
                                .build()
                                .expect("Failed to build tool result block"),
                        ))
                        .build()
                        .expect("Failed to build message"),
                );
            }

            // Continue the loop for next round
        }
    };

    Ok(stream)
}
