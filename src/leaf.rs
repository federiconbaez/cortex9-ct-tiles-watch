//! Data tiles: sequences of `TileLeaf` (c2sp.org/static-ct-api "Log
//! entries") and their RFC 6962 3.4 `MerkleTreeLeaf` hashes.

use crate::merkle::{self, Hash};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryType {
    X509,
    Precert,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub timestamp_ms: u64,
    pub entry_type: EntryType,
    /// x509_entry: the certificate DER. precert_entry: the TBSCertificate DER.
    pub signed_der: Vec<u8>,
    /// `leaf_index` from the CtExtensions, if present.
    pub leaf_index_ext: Option<u64>,
    pub leaf_hash: Hash,
    pub chain_len: usize,
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.b.len() {
            return Err("truncated TileLeaf".into());
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn uint(&mut self, n: usize) -> Result<u64, String> {
        Ok(self.take(n)?.iter().fold(0u64, |a, &x| (a << 8) | x as u64))
    }
    fn vec(&mut self, len_bytes: usize) -> Result<&'a [u8], String> {
        let n = self.uint(len_bytes)? as usize;
        self.take(n)
    }
}

/// Parse the CtExtensions of a TimestampedEntry; returns `leaf_index`.
pub fn parse_leaf_index(ext: &[u8]) -> Result<Option<u64>, String> {
    let mut r = Reader { b: ext, pos: 0 };
    let mut found = None;
    while r.pos < ext.len() {
        let ty = r.uint(1)?;
        let data = r.vec(2)?;
        if ty == 0 {
            if found.is_some() {
                return Err("duplicate leaf_index extension".into());
            }
            if data.len() != 5 {
                return Err("leaf_index is not 40 bits".into());
            }
            found = Some(data.iter().fold(0u64, |a, &x| (a << 8) | x as u64));
        }
    }
    Ok(found)
}

/// Parse every entry of a data tile.
pub fn parse_data_tile(bytes: &[u8]) -> Result<Vec<Entry>, String> {
    let mut r = Reader { b: bytes, pos: 0 };
    let mut out = Vec::new();
    while r.pos < bytes.len() {
        let start = r.pos;
        let timestamp_ms = r.uint(8)?;
        let et = r.uint(2)?;
        let (entry_type, signed_der) = match et {
            0 => (EntryType::X509, r.vec(3)?.to_vec()),
            1 => {
                let _issuer_key_hash = r.take(32)?;
                (EntryType::Precert, r.vec(3)?.to_vec())
            }
            other => return Err(format!("unknown entry_type {other}")),
        };
        let ext = r.vec(2)?;
        let te_end = r.pos;
        let leaf_index_ext = parse_leaf_index(ext)?;
        if entry_type == EntryType::Precert {
            let _pre_certificate = r.vec(3)?;
        }
        let chain = r.vec(2)?;
        if chain.len() % 32 != 0 {
            return Err("certificate_chain is not a list of fingerprints".into());
        }
        // MerkleTreeLeaf: version v1 (0), leaf_type timestamped_entry (0), TimestampedEntry.
        let mut mtl = Vec::with_capacity(2 + te_end - start);
        mtl.extend_from_slice(&[0, 0]);
        mtl.extend_from_slice(&bytes[start..te_end]);
        out.push(Entry {
            timestamp_ms,
            entry_type,
            signed_der,
            leaf_index_ext,
            leaf_hash: merkle::leaf_hash(&mtl),
            chain_len: chain.len() / 32,
        });
    }
    Ok(out)
}

/// Check a data tile against authenticated level-0 hashes and against the
/// `leaf_index` extension of each entry. `first_index` is tile_index * 256.
pub fn check_against(entries: &[Entry], hashes: &[Hash], first_index: u64) -> Result<(), String> {
    if entries.len() != hashes.len() {
        return Err(format!(
            "data tile has {} entries, level-0 tile {}",
            entries.len(),
            hashes.len()
        ));
    }
    for (i, (e, h)) in entries.iter().zip(hashes).enumerate() {
        if &e.leaf_hash != h {
            return Err(format!(
                "entry {} does not hash to its level-0 hash",
                first_index + i as u64
            ));
        }
        if let Some(li) = e.leaf_index_ext {
            if li != first_index + i as u64 {
                return Err(format!(
                    "entry {} carries leaf_index {li}",
                    first_index + i as u64
                ));
            }
        }
    }
    Ok(())
}
