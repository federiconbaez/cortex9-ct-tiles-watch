//! Directory-backed tile sources: replay for offline tests, recording for
//! capturing fixtures from a live log.

use crate::tiles::TileSource;
use std::cell::RefCell;
use std::io::Read;
use std::path::PathBuf;

/// Undo gzip if the body is gzip-compressed (static-ct-api allows data tiles
/// to be served compressed); TileLeaf bodies never start with 1f 8b.
pub fn maybe_gunzip(b: Vec<u8>) -> Result<Vec<u8>, String> {
    if b.len() >= 2 && b[0] == 0x1f && b[1] == 0x8b {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&b[..])
            .read_to_end(&mut out)
            .map_err(|e| format!("gunzip: {e}"))?;
        Ok(out)
    } else {
        Ok(b)
    }
}

/// Replays `<dir>/<path>.gz` files.
pub struct DirSource {
    pub dir: PathBuf,
}

impl TileSource for DirSource {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        let p = self.dir.join(format!("{path}.gz"));
        let b = std::fs::read(&p).map_err(|_| format!("missing fixture {path}"))?;
        maybe_gunzip(b)
    }
}

/// Wraps a source and stores everything it serves as `<dir>/<path>.gz`.
pub struct Recorder<'a, S: TileSource> {
    pub inner: &'a S,
    pub dir: PathBuf,
    pub paths: RefCell<Vec<String>>,
}

impl<S: TileSource> TileSource for Recorder<'_, S> {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        let b = self.inner.get(path)?;
        let p = self.dir.join(format!("{path}.gz"));
        std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        std::io::Write::write_all(&mut enc, &b).map_err(|e| e.to_string())?;
        std::fs::write(&p, enc.finish().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        self.paths.borrow_mut().push(path.to_string());
        Ok(b)
    }
}
