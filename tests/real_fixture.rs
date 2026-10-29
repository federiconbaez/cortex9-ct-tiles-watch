//! Offline checks on public data captured from Let's Encrypt Sycamore2026h2
//! (checkpoint, the tiles that authenticate one data tile, and that data
//! tile) and a Geomys Tuscolo2026h2 checkpoint. See tests/fixtures/README.md.

use ct_tiles_watch::checkpoint;
use ct_tiles_watch::fixture::DirSource;
use ct_tiles_watch::leaf::{self, EntryType};
use ct_tiles_watch::logs;
use ct_tiles_watch::names;
use ct_tiles_watch::tiles::{self, TileSource, TreeView, WIDTH};
use std::path::PathBuf;

const SYC: &str = "Let's Encrypt Sycamore2026h2";
const TUS: &str = "Geomys Tuscolo2026h2";
const TILE: u64 = 4093710;

fn dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn note(name: &str) -> String {
    std::fs::read_to_string(dir(name).join("checkpoint")).unwrap()
}

#[test]
fn real_checkpoints_verify_with_pinned_keys() {
    let l = logs::pinned();
    let c = checkpoint::verify(
        &note("sycamore2026h2"),
        &l.by_description(SYC).unwrap().key(),
    )
    .unwrap();
    assert_eq!(c.origin, "log.sycamore.ct.letsencrypt.org/2026h2");
    assert_eq!(c.size, 1047990054);
    assert!(c.timestamp_ms > 1_780_000_000_000);
    let t = checkpoint::verify(
        &note("tuscolo2026h2"),
        &l.by_description(TUS).unwrap().key(),
    )
    .unwrap();
    assert_eq!(t.origin, "tuscolo2026h2.sunlight.geomys.org");
}

#[test]
fn checkpoint_negative_controls() {
    let l = logs::pinned();
    let key = l.by_description(SYC).unwrap().key();
    let n = note("sycamore2026h2");
    // Wrong key (another log) and wrong origin.
    assert!(checkpoint::verify(&n, &l.by_description(TUS).unwrap().key()).is_err());
    assert!(checkpoint::verify(&note("tuscolo2026h2"), &key).is_err());
    // Size changed.
    let s = n.replacen("1047990054", "1047990055", 1);
    assert!(checkpoint::verify(&s, &key)
        .unwrap_err()
        .contains("does not verify"));
    // Root changed.
    let mut lines: Vec<String> = n.split('\n').map(String::from).collect();
    let mut r = lines[2].clone().into_bytes();
    r[0] = if r[0] == b'A' { b'B' } else { b'A' };
    lines[2] = String::from_utf8(r).unwrap();
    assert!(checkpoint::verify(&lines.join("\n"), &key).is_err());
    // Extension line.
    let ext = n.replacen("\n\n", "\nextension\n\n", 1);
    assert!(checkpoint::verify(&ext, &key).is_err());
    // Only the log's RFC 6962 signature removed: cosignatures must not count.
    let without: String = n
        .split_inclusive('\n')
        .filter(|l| {
            !(l.starts_with("\u{2014} log.sycamore") && {
                let b = l.trim_end().rsplit(' ').next().unwrap();
                ct_tiles_watch_b64(b).map(|v| v.len() > 80).unwrap_or(false)
            })
        })
        .collect();
    assert_ne!(without, n);
    assert!(checkpoint::verify(&without, &key)
        .unwrap_err()
        .contains("no signature"));
    // Non-canonical size.
    assert!(checkpoint::verify(&n.replacen("\n1047990054\n", "\n01047990054\n", 1), &key).is_err());
}

fn ct_tiles_watch_b64(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn view_parts() -> (checkpoint::Checkpoint, DirSource) {
    let l = logs::pinned();
    let c = checkpoint::verify(
        &note("sycamore2026h2"),
        &l.by_description(SYC).unwrap().key(),
    )
    .unwrap();
    (
        c,
        DirSource {
            dir: dir("sycamore2026h2"),
        },
    )
}

#[test]
fn real_tiles_authenticate_and_data_tile_hashes() {
    let (c, src) = view_parts();
    let mut v = TreeView::new(c.size, c.root, &src);
    v.verify_root().unwrap();
    let hashes = v.leaf_hashes(TILE).unwrap();
    let raw = src.get(&tiles::data_tile_path(TILE, WIDTH)).unwrap();
    let es = leaf::parse_data_tile(&raw).unwrap();
    assert_eq!(es.len(), 256);
    leaf::check_against(&es, &hashes, TILE * WIDTH).unwrap();
    assert!(es.iter().all(|e| e.leaf_index_ext.is_some()));
    assert!(es.iter().any(|e| e.entry_type == EntryType::Precert));
    let (mut named, mut ip_only) = (0, 0);
    for e in &es {
        let ns = names::names(e).unwrap();
        assert!(names::serial(e).unwrap().len() >= 8);
        if ns.is_empty() {
            // The only entries without a DNS name are IP-address certificates.
            assert!(names::ip_sans(e).unwrap() > 0);
            ip_only += 1;
        } else {
            named += 1;
        }
    }
    assert_eq!((named, ip_only), (224, 32));
}

#[test]
fn real_tiles_negative_controls() {
    let (c, src) = view_parts();
    // Forged root.
    let mut bad = c.root;
    bad[9] ^= 4;
    assert!(TreeView::new(c.size, bad, &src).verify_root().is_err());
    // Tampered data tile bytes, at several offsets.
    let mut v = TreeView::new(c.size, c.root, &src);
    let hashes = v.leaf_hashes(TILE).unwrap();
    let raw = src.get(&tiles::data_tile_path(TILE, WIDTH)).unwrap();
    for off in [9, 200, raw.len() / 3, raw.len() / 2, raw.len() - 40] {
        let mut b = raw.clone();
        b[off] ^= 1;
        let r = leaf::parse_data_tile(&b)
            .and_then(|es| leaf::check_against(&es, &hashes, TILE * WIDTH));
        // Bytes outside the TimestampedEntry (pre_certificate, chain) are not
        // covered by the leaf hash; flag which ones were caught.
        if off == 9 || off == 200 {
            assert!(r.is_err(), "offset {off} accepted");
        }
    }
    // Wrong position: the same tile claimed as the next index.
    let es = leaf::parse_data_tile(&raw).unwrap();
    assert!(leaf::check_against(&es, &hashes, (TILE + 1) * WIDTH).is_err());
    // Swapped entries.
    let mut sw = es.clone();
    sw.swap(0, 1);
    assert!(leaf::check_against(&sw, &hashes, TILE * WIDTH).is_err());
    // Missing tile file.
    assert!(v.leaf_hashes(TILE - 1).is_err());
}
