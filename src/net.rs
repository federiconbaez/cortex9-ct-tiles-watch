//! Bounded HTTP fetching with byte and request accounting.

use crate::tiles::TileSource;
use std::cell::{Cell, RefCell};
use std::io::Read;
use std::time::{Duration, Instant};

pub const USER_AGENT: &str = "ct-tiles-watch/0.1 (research monitor; small bounded reads)";

pub struct Http {
    agent: ureq::Agent,
    deadline: Option<Instant>,
    pub max_bytes: u64,
    pub bytes: Cell<u64>,
    pub requests: Cell<u64>,
    pub errors: RefCell<Vec<String>>,
}

impl Http {
    pub fn new(timeout: Duration, budget: Option<Duration>, max_bytes: u64) -> Http {
        Http {
            agent: ureq::AgentBuilder::new()
                .timeout(timeout)
                .user_agent(USER_AGENT)
                .build(),
            deadline: budget.map(|b| Instant::now() + b),
            max_bytes,
            bytes: Cell::new(0),
            requests: Cell::new(0),
            errors: RefCell::new(Vec::new()),
        }
    }

    /// GET with up to `tries` attempts. Body bytes after gzip decoding.
    pub fn get(&self, url: &str, tries: u32) -> Result<Vec<u8>, String> {
        let mut last = String::new();
        for attempt in 0..tries {
            if let Some(d) = self.deadline {
                if Instant::now() > d {
                    return Err("time budget exhausted".into());
                }
            }
            if self.bytes.get() > self.max_bytes {
                return Err("byte budget exhausted".into());
            }
            self.requests.set(self.requests.get() + 1);
            match self
                .agent
                .get(url)
                .set("Accept-Encoding", "gzip, identity")
                .call()
            {
                Ok(resp) => {
                    let mut buf = Vec::new();
                    resp.into_reader()
                        .take(64 << 20)
                        .read_to_end(&mut buf)
                        .map_err(|e| e.to_string())?;
                    self.bytes.set(self.bytes.get() + buf.len() as u64);
                    return Ok(buf);
                }
                Err(ureq::Error::Status(code, _)) => {
                    last = format!("HTTP {code}");
                    if code == 404 {
                        break;
                    }
                }
                Err(e) => last = e.to_string(),
            }
            std::thread::sleep(Duration::from_millis(500 * (attempt as u64 + 1)));
        }
        self.errors.borrow_mut().push(format!("{url}: {last}"));
        Err(last)
    }
}

/// Tiles of one log over HTTP.
pub struct HttpTiles<'a> {
    pub http: &'a Http,
    pub prefix: String,
}

impl TileSource for HttpTiles<'_> {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        let url = format!("{}{}", self.prefix, path);
        crate::fixture::maybe_gunzip(self.http.get(&url, 3)?)
    }
}
