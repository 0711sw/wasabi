/// Errors that can occur during PDF generation.
#[derive(Debug, thiserror::Error)]
pub enum PdfError {
    /// The template could not be read or resolved.
    #[error("template error: {0}")]
    Template(String),
    /// Typst compilation or PDF export failed.
    #[error("compile error: {0}")]
    Compile(String),
    /// A remote resource could not be fetched.
    #[error("failed to fetch {url}: {source}")]
    Fetch {
        /// The URL that was being fetched.
        url: String,
        /// The underlying reqwest error.
        source: reqwest::Error,
    },
    /// A barcode could not be generated.
    #[error("barcode error: {0}")]
    Barcode(String),
}
