//! DNS names of an entry and the per-domain filter.

use crate::leaf::{Entry, EntryType};
use x509_parser::certificate::TbsCertificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Lowercased dNSName SANs and subject CNs. Errors when the DER does not parse.
pub fn names(entry: &Entry) -> Result<Vec<String>, String> {
    let tbs_names = |tbs: &TbsCertificate| -> Vec<String> {
        let mut v = Vec::new();
        if let Ok(Some(san)) = tbs.subject_alternative_name() {
            for g in &san.value.general_names {
                if let GeneralName::DNSName(d) = g {
                    v.push(d.to_ascii_lowercase());
                }
            }
        }
        for cn in tbs.subject.iter_common_name() {
            if let Ok(s) = cn.as_str() {
                v.push(s.to_ascii_lowercase());
            }
        }
        v.sort();
        v.dedup();
        v
    };
    match entry.entry_type {
        EntryType::X509 => {
            let (_, c) = X509Certificate::from_der(&entry.signed_der).map_err(|e| e.to_string())?;
            Ok(tbs_names(&c.tbs_certificate))
        }
        EntryType::Precert => {
            let (_, t) = TbsCertificate::from_der(&entry.signed_der).map_err(|e| e.to_string())?;
            Ok(tbs_names(&t))
        }
    }
}

/// Serial number bytes of the entry's certificate or TBSCertificate.
pub fn serial(entry: &Entry) -> Result<Vec<u8>, String> {
    match entry.entry_type {
        EntryType::X509 => {
            let (_, c) = X509Certificate::from_der(&entry.signed_der).map_err(|e| e.to_string())?;
            Ok(c.tbs_certificate.raw_serial().to_vec())
        }
        EntryType::Precert => {
            let (_, t) = TbsCertificate::from_der(&entry.signed_der).map_err(|e| e.to_string())?;
            Ok(t.raw_serial().to_vec())
        }
    }
}

/// `name` is `domain` or a subdomain of it (label boundary), ignoring case,
/// a trailing dot and a leading wildcard label.
pub fn matches(name: &str, domain: &str) -> bool {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let n = n.strip_prefix("*.").unwrap_or(&n);
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    n == d || n.ends_with(&format!(".{d}"))
}

/// Number of iPAddress SANs (short-lived IP certificates carry no DNS name).
pub fn ip_sans(entry: &Entry) -> Result<usize, String> {
    let count = |tbs: &TbsCertificate| -> usize {
        match tbs.subject_alternative_name() {
            Ok(Some(san)) => san
                .value
                .general_names
                .iter()
                .filter(|g| matches!(g, GeneralName::IPAddress(_)))
                .count(),
            _ => 0,
        }
    };
    match entry.entry_type {
        EntryType::X509 => {
            let (_, c) = X509Certificate::from_der(&entry.signed_der).map_err(|e| e.to_string())?;
            Ok(count(&c.tbs_certificate))
        }
        EntryType::Precert => {
            let (_, t) = TbsCertificate::from_der(&entry.signed_der).map_err(|e| e.to_string())?;
            Ok(count(&t))
        }
    }
}
