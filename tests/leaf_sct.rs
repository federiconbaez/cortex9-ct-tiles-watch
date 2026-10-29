use ct_tiles_watch::leaf::{self, EntryType};
use ct_tiles_watch::logs;
use ct_tiles_watch::merkle;
use ct_tiles_watch::sct;

#[test]
fn leaf_index_extension() {
    // Extensions of a real SCT (l10n.debian.org, see below).
    assert_eq!(
        leaf::parse_leaf_index(&[0, 0, 5, 0, 7, 0x3e, 0xaa, 0x94]).unwrap(),
        Some(0x073eaa94)
    );
    assert_eq!(leaf::parse_leaf_index(&[]).unwrap(), None);
    // Unknown extension type is skipped.
    assert_eq!(
        leaf::parse_leaf_index(&[9, 0, 1, 0xff, 0, 0, 5, 0, 0, 0, 0, 2]).unwrap(),
        Some(2)
    );
    assert!(leaf::parse_leaf_index(&[0, 0, 4, 0, 0, 0, 1]).is_err());
    assert!(leaf::parse_leaf_index(&[0, 0, 5, 0, 0]).is_err());
    assert!(leaf::parse_leaf_index(&[0, 0, 5, 0, 0, 0, 0, 1, 0, 0, 5, 0, 0, 0, 0, 1]).is_err());
}

fn synthetic_x509_leaf(ts: u64, cert: &[u8], idx: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&ts.to_be_bytes());
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
    b.extend_from_slice(cert);
    b.extend_from_slice(&[0, 8, 0, 0, 5]);
    b.extend_from_slice(&idx.to_be_bytes()[3..]);
    b.extend_from_slice(&[0, 32]);
    b.extend_from_slice(&[0xaa; 32]);
    b
}

#[test]
fn synthetic_tile_leaf_hash_follows_rfc6962() {
    let a = synthetic_x509_leaf(1000, b"certA", 0);
    let b = synthetic_x509_leaf(1001, b"certB", 1);
    let es = leaf::parse_data_tile(&[a.clone(), b].concat()).unwrap();
    assert_eq!(es.len(), 2);
    assert_eq!(es[0].entry_type, EntryType::X509);
    assert_eq!(es[1].leaf_index_ext, Some(1));
    assert_eq!(es[0].chain_len, 1);
    // MerkleTreeLeaf = 0x00 version, 0x00 leaf type, TimestampedEntry (no chain).
    let te = &a[..a.len() - 34];
    assert_eq!(
        es[0].leaf_hash,
        merkle::leaf_hash(&[&[0u8, 0][..], te].concat())
    );
    let hashes = [es[0].leaf_hash, es[1].leaf_hash];
    leaf::check_against(&es, &hashes, 0).unwrap();
    // Position disagreeing with leaf_index is rejected even if hashes match.
    assert!(leaf::check_against(&es, &hashes, 256).is_err());
    // Truncations are errors, not panics.
    for cut in 1..a.len() {
        assert!(leaf::parse_data_tile(&a[..cut]).is_err(), "cut {cut}");
    }
    let mut bad = a.clone();
    bad[9] = 7; // entry_type 7
    assert!(leaf::parse_data_tile(&bad).is_err());
}

#[test]
fn real_certificate_scts() {
    // l10n.debian.org, downloaded from crt.sh (id 29999478302), public data.
    let pem = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/l10n.debian.org.pem"
    ))
    .unwrap();
    let der = sct::to_der(&pem).unwrap();
    assert_eq!(der[0], 0x30);
    let scts = sct::embedded(&der).unwrap();
    assert!(scts.len() >= 2);
    let list = logs::pinned();
    let tiled: Vec<_> = scts
        .iter()
        .filter(|s| list.by_log_id(&s.log_id).is_some())
        .collect();
    assert_eq!(tiled.len(), 1);
    assert_eq!(tiled[0].leaf_index, Some(0x073eaa94));
    // SCTs from RFC 6962 (non-tiled) logs carry no leaf_index.
    assert!(scts
        .iter()
        .filter(|s| list.by_log_id(&s.log_id).is_none())
        .all(|s| s.leaf_index.is_none()));
    assert!(!sct::serial(&der).unwrap().is_empty());
    // DER passes through unchanged.
    assert_eq!(sct::to_der(&der).unwrap(), der);
}
