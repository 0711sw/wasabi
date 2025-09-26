use crate::scripts::compiler::span::{ByteSpan, LineStarts};
use crate::scripts::compiler::{Message, Severity};

pub struct CompilationContext {
    pub messages: Vec<Message>,
    pub line_starts: LineStarts,
}

impl CompilationContext {
    pub fn new(source: &str) -> Self {
        Self {
            messages: vec![],
            line_starts: LineStarts::new(source),
        }
    }

    pub fn error(&mut self, span: &ByteSpan, message: impl ToString) {
        self.messages.push(Message {
            severity: Severity::Error,
            span: self.line_starts.to_char_span(span),
            message: message.to_string(),
        })
    }

    pub fn warning(&mut self, span: &ByteSpan, message: impl ToString) {
        self.messages.push(Message {
            severity: Severity::Warning,
            span: self.line_starts.to_char_span(span),
            message: message.to_string(),
        })
    }

    pub fn is_ok(&self) -> bool {
        !self.messages.iter().any(|m| m.severity == Severity::Error)
    }

    pub fn messages(self) -> Vec<Message> {
        self.messages
    }
}
