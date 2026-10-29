//! Checkpoints (c2sp.org/tlog-checkpoint) signed as notes
//! (c2sp.org/signed-note) with RFC 6962 `TreeHeadSignature`s
//! (c2sp.org/static-ct-api "Checkpoints", RFC 6962 section 3.5).

use crate::merkle::Hash;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: Hash,
    /// Timestamp (ms) of the verified RFC 6962 signature.
    pub timestamp_ms: u64,
    pub raw: String,
}

/// A static-ct log key: SPKI DER of an ECDSA P-256 key.
pub struct LogKey {
    pub origin: String,
    pub spki_der: Vec<u8>,
}

impl LogKey {
    /// RFC 6962 3.2 LogID: SHA-256 of the DER public key.
    pub fn log_id(&self) -> Hash {
        Sha256::digest(&self.spki_der).into()
    }

    /// static-ct-api: SHA-256(name || 0x0A || 0x05 || LogID)[:4].
    pub fn key_id(&self) -> [u8; 4] {
        let mut h = Sha256::new();
        h.update(self.origin.as_bytes());
        h.update([0x0a, 0x05]);
        h.update(self.log_id());
        let d = h.finalize();
        [d[0], d[1], d[2], d[3]]
    }
}

fn b64_canonical(s: &str) -> Result<Vec<u8>, String> {
    let v = STANDARD.decode(s).map_err(|e| format!("base64: {e}"))?;
    if STANDARD.encode(&v) != s {
        return Err("non-canonical base64".into());
    }
    Ok(v)
}

/// Parse and verify. Signatures from unknown keys are ignored; the log's
/// RFC 6962 signature must be present and valid.
pub fn verify(note: &str, key: &LogKey) -> Result<Checkpoint, String> {
    if note.bytes().any(|b| b < 0x20 && b != b'\n') {
        return Err("control character in note".into());
    }
    let sep = note
        .rfind("\n\n")
        .ok_or("no blank line before signatures")?;
    let text = &note[..sep + 1];
    let sigs = &note[sep + 2..];
    let lines: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
    if lines.len() < 3 {
        return Err("checkpoint text has fewer than three lines".into());
    }
    if lines.len() > 3 {
        // static-ct-api: RFC 6962 signed checkpoints MUST NOT have extension lines.
        return Err("extension lines are not allowed with RFC 6962 signatures".into());
    }
    let origin = lines[0].to_string();
    if origin != key.origin {
        return Err(format!("origin {origin} does not match the configured log"));
    }
    let size_s = lines[1];
    if size_s.is_empty() || (size_s.len() > 1 && size_s.starts_with('0')) {
        return Err("tree size is not a canonical decimal".into());
    }
    let size: u64 = size_s.parse().map_err(|_| "tree size is not a number")?;
    let root_v = b64_canonical(lines[2])?;
    let root: Hash = root_v.try_into().map_err(|_| "root hash is not 32 bytes")?;

    let vk = VerifyingKey::from_public_key_der(&key.spki_der).map_err(|e| format!("key: {e}"))?;
    let want_id = key.key_id();
    let mut verified: Option<u64> = None;
    for line in sigs.lines() {
        let rest = line
            .strip_prefix("\u{2014} ")
            .ok_or("malformed signature line")?;
        let (name, b64) = rest.split_once(' ').ok_or("malformed signature line")?;
        if name != key.origin {
            continue;
        }
        let blob = b64_canonical(b64)?;
        if blob.len() < 4 || blob[..4] != want_id {
            continue; // same name, other key or algorithm: ignored
        }
        let body = &blob[4..];
        // struct { uint64 timestamp; TreeHeadSignature signature; }
        // where the signature is a DigitallySigned: hash(1) sig(1) opaque<0..2^16-1>.
        if body.len() < 12 {
            return Err("RFC 6962 note signature too short".into());
        }
        let ts = u64::from_be_bytes(body[..8].try_into().unwrap());
        let (hash_alg, sig_alg) = (body[8], body[9]);
        let len = u16::from_be_bytes([body[10], body[11]]) as usize;
        if body.len() != 12 + len {
            return Err("RFC 6962 note signature length mismatch".into());
        }
        if hash_alg != 4 || sig_alg != 3 {
            return Err("only sha256/ecdsa TreeHeadSignatures are supported".into());
        }
        let sig = DerSignature::from_bytes(&body[12..]).map_err(|e| format!("sig: {e}"))?;
        let mut signed = Vec::with_capacity(50);
        signed.push(0u8); // version v1
        signed.push(1u8); // signature_type tree_hash
        signed.extend_from_slice(&ts.to_be_bytes());
        signed.extend_from_slice(&size.to_be_bytes());
        signed.extend_from_slice(&root);
        vk.verify(&signed, &sig)
            .map_err(|_| "RFC 6962 tree head signature does not verify".to_string())?;
        verified = Some(ts);
    }
    let timestamp_ms = verified.ok_or("no signature from the log key")?;
    Ok(Checkpoint {
        origin,
        size,
        root,
        timestamp_ms,
        raw: note.to_string(),
    })
}
