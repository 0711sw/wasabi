//! AWS Bedrock AI model integration for streaming responses.
//!
//! Provides helpers for consuming Bedrock's `ConverseStream` API and converting
//! events to Server-Sent Events (SSE) for web clients.
//!
//! # Event Types
//!
//! - `content` - Text chunks from the model
//! - `toolUse` - Tool/function call requests
//! - `usage` - Token usage metadata
//! - `done` - Stream completion signal
//! - `error` - Error messages

use aws_sdk_bedrockruntime::primitives::event_stream::EventReceiver;
use aws_sdk_bedrockruntime::types::error::ConverseStreamOutputError;
use aws_sdk_bedrockruntime::types::{ConverseStreamOutput, ToolUseBlockStart};
use serde_json::json;
use warp::sse::Event;

/// Events emitted by Bedrock model responses.
pub enum ModelEvent {
    /// A text chunk from the model's response.
    Text(String),
    /// A tool/function call request from the model.
    ToolUse(ToolUse),
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
#[derive(Default, Debug)]
pub struct ToolUse {
    /// Unique ID for correlating tool results.
    id: String,
    /// Tool name to invoke.
    name: String,
    /// JSON-encoded tool arguments.
    input: String,
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
            Err(e) => return Err(e.to_string()),
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
            Err(e) => return Err(e.to_string()),
        }
    }
}
