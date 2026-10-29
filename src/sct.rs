//! Embedded SCTs (RFC 6962 3.3) and their static-ct `leaf_index`.

use crate::leaf::parse_leaf_index;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sct {
    pub log_id: [u8; 32],
    pub timestamp_ms: u64,
    pub leaf_index: Option<u64>,
}

/// Accept DER or a single PEM `CERTIFICATE` block (crt.sh `?d=` serves PEM).
pub fn to_der(b: &[u8]) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let Ok(text) = std::str::from_utf8(b) else {
        return Ok(b.to_vec());
    };
    let Some(start) = text.find("-----BEGIN CERTIFICATE-----") else {
        return Ok(b.to_vec());
    };
    let body = &text[start + 27..];
    let end = body
        .find("-----END CERTIFICATE-----")
        .ok_or("unterminated PEM")?;
    let b64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("PEM base64: {e}"))
}

/// SCTs embedded in a final certificate. Empty for precertificates.
pub fn embedded(cert_der: &[u8]) -> Result<Vec<Sct>, String> {
    let (_, c) = X509Certificate::from_der(cert_der).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for ext in c.extensions() {
        if let ParsedExtension::SCT(list) = ext.parsed_extension() {
            for s in list {
                out.push(Sct {
                    log_id: *s.id.key_id,
                    timestamp_ms: s.timestamp,
                    leaf_index: parse_leaf_index(s.extensions.0)?,
                });
            }
        }
    }
    Ok(out)
}

/// Serial number bytes of a certificate.
pub fn serial(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    let (_, c) = X509Certificate::from_der(cert_der).map_err(|e| e.to_string())?;
    Ok(c.tbs_certificate.raw_serial().to_vec())
}
