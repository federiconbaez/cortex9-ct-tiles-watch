//! Tile arithmetic and authentication on synthetic trees, against a naive
//! RFC 6962 section 2.1 Merkle Tree Hash.

use ct_tiles_watch::merkle::{self, Hash};
use ct_tiles_watch::tiles::{self, TileSource, TreeView, WIDTH};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;

fn naive_mth(leaves: &[Vec<u8>]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest(b"").into(),
        1 => {
            let mut h = Sha256::new();
            h.update([0u8]);
            h.update(&leaves[0]);
            h.finalize().into()
        }
        n => {
            let mut k = 1;
            while k * 2 < n {
                k *= 2;
            }
            let mut h = Sha256::new();
            h.update([1u8]);
            h.update(naive_mth(&leaves[..k]));
            h.update(naive_mth(&leaves[k..]));
            h.finalize().into()
        }
    }
}

fn leaves(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("leaf {i}").into_bytes()).collect()
}

/// Serves the tiles of a tree of `size` leaves, full and partial.
struct Mem {
    files: RefCell<HashMap<String, Vec<u8>>>,
    gets: Cell<usize>,
}

impl Mem {
    fn new(ls: &[Vec<u8>]) -> Mem {
        let mut files = HashMap::new();
        let mut level: Vec<Hash> = ls.iter().map(|l| merkle::leaf_hash(l)).collect();
        let mut l = 0u8;
        while !level.is_empty() {
            let mut next = Vec::new();
            for (i, chunk) in level.chunks(WIDTH as usize).enumerate() {
                let bytes: Vec<u8> = chunk.concat();
                files.insert(
                    tiles::hash_tile_path(l, i as u64, chunk.len() as u64),
                    bytes,
                );
                if chunk.len() == WIDTH as usize {
                    next.push(merkle::mth_of_nodes(chunk));
                }
            }
            level = next;
            l += 1;
        }
        Mem {
            files: RefCell::new(files),
            gets: Cell::new(0),
        }
    }
}

impl TileSource for Mem {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        self.gets.set(self.gets.get() + 1);
        self.files
            .borrow()
            .get(path)
            .cloned()
            .ok_or_else(|| format!("404 {path}"))
    }
}

#[test]
fn index_paths_follow_tlog_tiles() {
    // Examples from c2sp.org/tlog-tiles.
    assert_eq!(tiles::index_path(1234067), "x001/x234/067");
    assert_eq!(tiles::index_path(0), "000");
    assert_eq!(tiles::index_path(999), "999");
    assert_eq!(tiles::index_path(1000), "x001/000");
    assert_eq!(
        tiles::hash_tile_path(0, 1234067, 256),
        "tile/0/x001/x234/067"
    );
    assert_eq!(
        tiles::hash_tile_path(0, 1234067, 128),
        "tile/0/x001/x234/067.p/128"
    );
    assert_eq!(tiles::data_tile_path(5, 7), "tile/data/005.p/7");
}

#[test]
fn tile_widths() {
    assert_eq!(tiles::tile_width(256, 0, 0), 256);
    assert_eq!(tiles::tile_width(256, 0, 1), 0);
    assert_eq!(tiles::tile_width(256, 1, 0), 1);
    assert_eq!(tiles::tile_width(70000, 0, 273), 112);
    assert_eq!(tiles::tile_width(70000, 1, 1), 17);
    assert_eq!(tiles::tile_width(70000, 2, 0), 1);
    assert_eq!(tiles::tile_width(70000, 2, 1), 0);
}

const SIZES: &[usize] = &[
    1, 2, 3, 7, 255, 256, 257, 511, 512, 1000, 65535, 65536, 65537, 70000,
];

#[test]
fn root_from_tiles_equals_naive_mth() {
    for &n in SIZES {
        let ls = leaves(n);
        let src = Mem::new(&ls);
        let mut v = TreeView::new(n as u64, naive_mth(&ls), &src);
        v.verify_root().unwrap_or_else(|e| panic!("size {n}: {e}"));
    }
}

#[test]
fn prefix_roots_and_consistency() {
    let n = 70000usize;
    let ls = leaves(n);
    let src = Mem::new(&ls);
    let mut v = TreeView::new(n as u64, naive_mth(&ls), &src);
    for &m in &[
        1usize, 2, 255, 256, 257, 4096, 65535, 65536, 65537, 69999, 70000,
    ] {
        let want = naive_mth(&ls[..m]);
        assert_eq!(v.root_at(m as u64).unwrap(), want, "m={m}");
        v.consistent_with(m as u64, &want).unwrap();
        let mut bad = want;
        bad[5] ^= 0x80;
        assert!(
            v.consistent_with(m as u64, &bad).is_err(),
            "m={m} tampered accepted"
        );
    }
}

#[test]
fn wrong_root_is_rejected() {
    let ls = leaves(1000);
    let src = Mem::new(&ls);
    let mut root = naive_mth(&ls);
    root[0] ^= 1;
    assert!(TreeView::new(1000, root, &src).verify_root().is_err());
    // Correct root but for a different size.
    assert!(TreeView::new(999, naive_mth(&ls), &src)
        .verify_root()
        .is_err());
}

#[test]
fn tampered_full_tile_is_rejected() {
    let n = 70000usize;
    let ls = leaves(n);
    let src = Mem::new(&ls);
    let p = tiles::hash_tile_path(0, 3, 256);
    src.files.borrow_mut().get_mut(&p).unwrap()[100] ^= 1;
    let mut v = TreeView::new(n as u64, naive_mth(&ls), &src);
    v.verify_root().unwrap();
    let e = v.leaf_hashes(3).unwrap_err();
    assert!(e.contains("does not hash into its parent"), "{e}");
    assert!(v.leaf_hashes(4).is_ok());
    // A prefix whose root needs tile 0/3 cannot be computed either.
    assert!(v.root_at(3 * 256 + 10).is_err());
}

#[test]
fn tampered_level1_tile_is_rejected() {
    let n = 70000usize;
    let ls = leaves(n);
    let src = Mem::new(&ls);
    let p = tiles::hash_tile_path(1, 0, 256);
    src.files.borrow_mut().get_mut(&p).unwrap()[3 * 32] ^= 1;
    let mut v = TreeView::new(n as u64, naive_mth(&ls), &src);
    v.verify_root().unwrap();
    assert!(v.leaf_hashes(3).is_err());
}

#[test]
fn wrong_tile_length_is_rejected() {
    let ls = leaves(300);
    let src = Mem::new(&ls);
    let p = tiles::hash_tile_path(0, 1, 44);
    src.files
        .borrow_mut()
        .get_mut(&p)
        .unwrap()
        .truncate(43 * 32);
    assert!(TreeView::new(300, naive_mth(&ls), &src)
        .verify_root()
        .is_err());
}

#[test]
fn deleted_partial_tiles_fall_back_to_full_tiles() {
    // Older tree of 1000 served by the tiles of a newer tree of 70000, which
    // has no partial tiles for width 1000 % 256.
    let ls = leaves(70000);
    let src = Mem::new(&ls);
    let mut v = TreeView::new(1000, naive_mth(&ls[..1000]), &src);
    v.verify_root().unwrap();
    assert!(src.gets.get() > 0);
}
