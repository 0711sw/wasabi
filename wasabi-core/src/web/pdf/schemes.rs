//! Resolver functions for custom URI schemes used in Typst templates.

use std::path::Path;

use typst::foundations::Bytes;

use super::error::PdfError;

/// Serialize injected JSON data to bytes.
/// Used for the `data://` scheme — returns the same result regardless of path.
pub fn resolve_data(value: &serde_json::Value) -> Bytes {
    let json = serde_json::to_vec(value).unwrap_or_default();
    Bytes::new(json)
}

/// Generate a QR code as SVG bytes.
pub fn resolve_qr(data: &str) -> Result<Bytes, PdfError> {
    use fast_qr::QRBuilder;
    use fast_qr::convert::svg::SvgBuilder;

    let qr = QRBuilder::new(data)
        .build()
        .map_err(|e| PdfError::Barcode(format!("QR: {e}")))?;

    let svg = SvgBuilder::default().to_str(&qr);
    Ok(Bytes::new(svg.into_bytes()))
}

/// Generate an EAN-13 barcode as SVG bytes.
pub fn resolve_ean(code: &str) -> Result<Bytes, PdfError> {
    use rxing::Writer;
    use rxing::oned::EAN13Writer;

    let writer = EAN13Writer;
    let matrix = writer
        .encode(code, &rxing::BarcodeFormat::EAN_13, 0, 0)
        .map_err(|e| PdfError::Barcode(format!("EAN-13: {e}")))?;

    let width = matrix.width();
    let height = 60;
    let mut svg =
        format!(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">"#);
    for x in 0..width {
        if matrix.get(x, 0) {
            svg.push_str(&format!(
                r#"<rect x="{x}" y="0" width="1" height="{height}" fill="black"/>"#
            ));
        }
    }
    svg.push_str("</svg>");
    Ok(Bytes::new(svg.into_bytes()))
}

/// Fetch a resource over HTTPS. Uses blocking reqwest since this runs
/// inside typst's synchronous `World::file()` callback.
pub fn resolve_https(url: &str) -> Result<Bytes, PdfError> {
    let response = reqwest::blocking::get(url).map_err(|e| PdfError::Fetch {
        url: url.to_string(),
        source: e,
    })?;
    let bytes = response.bytes().map_err(|e| PdfError::Fetch {
        url: url.to_string(),
        source: e,
    })?;
    Ok(Bytes::new(bytes.to_vec()))
}

/// Read a file relative to the base directory.
pub fn resolve_local(base: &Path, path: &str) -> Result<Bytes, PdfError> {
    let full_path = base.join(path);
    let data = std::fs::read(&full_path)
        .map_err(|e| PdfError::Template(format!("failed to read {}: {e}", full_path.display())))?;
    Ok(Bytes::new(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_data() {
        let value = serde_json::json!({"name": "test", "amount": 42});
        let bytes = resolve_data(&value);
        let round_trip: serde_json::Value = serde_json::from_slice(bytes.as_slice()).unwrap();
        assert_eq!(round_trip, value);
    }

    #[test]
    fn test_resolve_qr() {
        let bytes = resolve_qr("hello").unwrap();
        let svg = std::str::from_utf8(bytes.as_slice()).unwrap();
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
    }

    #[test]
    fn test_resolve_ean() {
        let bytes = resolve_ean("4006381333931").unwrap();
        let svg = std::str::from_utf8(bytes.as_slice()).unwrap();
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
    }
}
