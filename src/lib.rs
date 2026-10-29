//! A small Certificate Transparency monitor for static-ct-api (tiled) logs.
//!
//! * [`merkle`]: RFC 6962 Merkle Tree Hash helpers.
//! * [`tiles`]: tile paths, authenticated tile access and checkpoint
//!   consistency computed from tiles (c2sp.org/tlog-tiles).
//! * [`checkpoint`]: checkpoint parsing and RFC 6962 note signatures
//!   (c2sp.org/tlog-checkpoint, c2sp.org/signed-note, c2sp.org/static-ct-api).
//! * [`leaf`]: data tile (`TileLeaf`) parsing and leaf hashes.
//! * [`names`]: DNS names of a certificate and the domain filter.
//! * [`sct`]: embedded SCTs and the static-ct `leaf_index` extension.
//! * [`logs`]: the pinned log list.
//! * [`net`]: bounded HTTP fetching with byte accounting.

pub mod checkpoint;
pub mod fixture;
pub mod leaf;
pub mod logs;
pub mod merkle;
pub mod names;
pub mod net;
pub mod sct;
pub mod tiles;
