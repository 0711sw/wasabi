use logos::Span;
use std::sync::Arc;

pub type ByteSpan = Span;

#[derive(Debug)]
pub struct CharSpan {
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
}

#[derive(Clone)]
pub struct LineStarts {
    line_starts: Arc<Vec<usize>>,
}

impl LineStarts {
    pub fn new(source: &str) -> Self {
        let mut line_starts = vec![];
        line_starts.push(0);
        for (i, c) in source.char_indices() {
            if c == '\n' {
                line_starts.push(i + 1);
            }
        }

        Self {
            line_starts: Arc::new(line_starts),
        }
    }

    pub fn to_char_span(&self, span: &ByteSpan) -> CharSpan {
        let start = span.start;
        let end = span.end;

        let start_line = self
            .line_starts
            .iter()
            .position(|&x| x > start)
            .unwrap_or(self.line_starts.len())
            - 1;
        let end_line = self
            .line_starts
            .iter()
            .position(|&x| x > end)
            .unwrap_or(self.line_starts.len())
            - 1;

        let start_col = if start_line < self.line_starts.len() {
            start - self.line_starts[start_line]
        } else {
            0
        };

        let end_col = if end_line < self.line_starts.len() {
            end - self.line_starts[end_line]
        } else {
            0
        };

        CharSpan {
            start_line: start_line + 1,
            start_col: start_col + 1,
            end_line: end_line + 1,
            end_col: end_col + 1,
        }
    }
}
