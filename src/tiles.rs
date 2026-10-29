//! Tiles (c2sp.org/tlog-tiles, c2sp.org/static-ct-api "Merkle Tree").
//!
//! A [`TreeView`] is a tree of a given size and root, whose tiles come from a
//! [`TileSource`]. Every tile used for a computation is authenticated: the
//! rightmost (partial) tiles by recomputing the checkpoint root, every full
//! tile by hashing it and comparing with its entry in the tile above.

use crate::merkle::{self, Hash};
use std::collections::{HashMap, HashSet};

pub const WIDTH: u64 = 256;

/// `<N>` path element: zero-padded 3-digit groups, all but the last with `x`.
pub fn index_path(n: u64) -> String {
    let mut groups = vec![format!("{:03}", n % 1000)];
    let mut rest = n / 1000;
    while rest > 0 {
        groups.push(format!("x{:03}", rest % 1000));
        rest /= 1000;
    }
    groups.reverse();
    groups.join("/")
}

/// `tile/<L>/<N>[.p/<W>]`
pub fn hash_tile_path(level: u8, index: u64, width: u64) -> String {
    let mut p = format!("tile/{level}/{}", index_path(index));
    if width < WIDTH {
        p.push_str(&format!(".p/{width}"));
    }
    p
}

/// `tile/data/<N>[.p/<W>]`
pub fn data_tile_path(index: u64, width: u64) -> String {
    let mut p = format!("tile/data/{}", index_path(index));
    if width < WIDTH {
        p.push_str(&format!(".p/{width}"));
    }
    p
}

fn pow256(l: u8) -> u64 {
    WIDTH.pow(l as u32)
}

/// Width of tile `index` at `level` in a tree of `size` (0 if it does not exist).
pub fn tile_width(size: u64, level: u8, index: u64) -> u64 {
    let span = pow256(level + 1);
    if (index + 1) * span <= size {
        WIDTH
    } else if index * span < size {
        size / pow256(level) - index * WIDTH
    } else {
        0
    }
}

/// Source of raw tile bytes by path.
pub trait TileSource {
    fn get(&self, path: &str) -> Result<Vec<u8>, String>;
}

pub struct TreeView<'a, S: TileSource> {
    pub size: u64,
    pub root: Hash,
    src: &'a S,
    cache: HashMap<(u8, u64), Vec<Hash>>,
    authenticated: HashSet<(u8, u64)>,
    edge_checked: bool,
}

fn split_hashes(bytes: &[u8]) -> Result<Vec<Hash>, String> {
    if bytes.len() % 32 != 0 {
        return Err(format!(
            "tile length {} is not a multiple of 32",
            bytes.len()
        ));
    }
    Ok(bytes
        .chunks(32)
        .map(|c| {
            let mut h = [0u8; 32];
            h.copy_from_slice(c);
            h
        })
        .collect())
}

impl<'a, S: TileSource> TreeView<'a, S> {
    pub fn new(size: u64, root: Hash, src: &'a S) -> Self {
        TreeView {
            size,
            root,
            src,
            cache: HashMap::new(),
            authenticated: HashSet::new(),
            edge_checked: false,
        }
    }

    /// Fetch (unauthenticated) the hashes of a tile as served for this tree.
    fn raw_tile(&mut self, level: u8, index: u64) -> Result<Vec<Hash>, String> {
        if let Some(t) = self.cache.get(&(level, index)) {
            return Ok(t.clone());
        }
        let w = tile_width(self.size, level, index);
        if w == 0 {
            return Err(format!(
                "tile {level}/{index} not in tree of size {}",
                self.size
            ));
        }
        // Partial tiles may be deleted once the full tile exists
        // (tlog-tiles); the first w hashes of the full tile are the same.
        let bytes = match self.src.get(&hash_tile_path(level, index, w)) {
            Ok(b) => b,
            Err(e) if w < WIDTH => {
                let full = self
                    .src
                    .get(&hash_tile_path(level, index, WIDTH))
                    .map_err(|_| e)?;
                full[..(w as usize * 32).min(full.len())].to_vec()
            }
            Err(e) => return Err(e),
        };
        let hashes = split_hashes(&bytes)?;
        if hashes.len() as u64 != w {
            return Err(format!(
                "tile {level}/{index}: {} hashes, expected {w}",
                hashes.len()
            ));
        }
        self.cache.insert((level, index), hashes.clone());
        Ok(hashes)
    }

    fn levels(size: u64) -> u8 {
        let mut l = 0u8;
        while pow256(l) <= size && l < 63 {
            l += 1;
        }
        l
    }

    /// Perfect subtrees of the tree of size `m`, left to right, built from
    /// the tiles of this tree. `authenticate` decides whether every tile is
    /// checked before use.
    fn subtrees(&mut self, m: u64, authenticate: bool) -> Result<Vec<Hash>, String> {
        let mut out = Vec::new();
        for level in (0..Self::levels(m)).rev() {
            let w = (m / pow256(level)) % WIDTH;
            if w == 0 {
                continue;
            }
            let index = m / pow256(level + 1);
            if authenticate {
                self.authenticate(level, index)?;
            }
            let t = self.raw_tile(level, index)?;
            let nodes = &t[..w as usize];
            // Decompose w into powers of two, largest first.
            let mut start = 0usize;
            let mut bit = 128usize;
            while bit > 0 {
                if (w as usize) & bit != 0 {
                    out.push(merkle::mth_of_nodes(&nodes[start..start + bit]));
                    start += bit;
                }
                bit >>= 1;
            }
        }
        Ok(out)
    }

    /// Recompute the root of this tree from its rightmost tiles and compare
    /// with the checkpoint root. Authenticates those tiles.
    pub fn verify_root(&mut self) -> Result<(), String> {
        if self.edge_checked {
            return Ok(());
        }
        let subtrees = self.subtrees(self.size, false)?;
        if merkle::fold_subtrees(&subtrees) != self.root {
            return Err("root recomputed from tiles does not match checkpoint".into());
        }
        for level in 0..Self::levels(self.size) {
            let index = self.size / pow256(level + 1);
            if tile_width(self.size, level, index) > 0 {
                self.authenticated.insert((level, index));
            }
        }
        self.edge_checked = true;
        Ok(())
    }

    /// Authenticate a tile against the checkpoint root.
    pub fn authenticate(&mut self, level: u8, index: u64) -> Result<(), String> {
        self.verify_root()?;
        if self.authenticated.contains(&(level, index)) {
            return Ok(());
        }
        if tile_width(self.size, level, index) != WIDTH {
            return Err(format!("tile {level}/{index} is neither full nor the edge"));
        }
        let t = self.raw_tile(level, index)?;
        let parent = (level + 1, index / WIDTH);
        self.authenticate(parent.0, parent.1)?;
        let p = self.raw_tile(parent.0, parent.1)?;
        if merkle::mth_of_nodes(&t) != p[(index % WIDTH) as usize] {
            return Err(format!(
                "tile {level}/{index} does not hash into its parent"
            ));
        }
        self.authenticated.insert((level, index));
        Ok(())
    }

    /// Authenticated level-0 hashes of tile `index`.
    pub fn leaf_hashes(&mut self, index: u64) -> Result<Vec<Hash>, String> {
        self.authenticate(0, index)?;
        self.raw_tile(0, index)
    }

    /// Root of the prefix of size `m` (m <= size), from authenticated tiles.
    pub fn root_at(&mut self, m: u64) -> Result<Hash, String> {
        if m > self.size {
            return Err("prefix larger than tree".into());
        }
        self.verify_root()?;
        let s = self.subtrees(m, true)?;
        Ok(merkle::fold_subtrees(&s))
    }

    /// Checkpoint `(m, root_m)` is consistent with this tree.
    pub fn consistent_with(&mut self, m: u64, root_m: &Hash) -> Result<(), String> {
        let r = self.root_at(m)?;
        if &r != root_m {
            return Err(format!("prefix of size {m} has a different root"));
        }
        Ok(())
    }

    /// Number of tile fetches served so far (cache misses).
    pub fn tiles_fetched(&self) -> usize {
        self.cache.len()
    }
}
