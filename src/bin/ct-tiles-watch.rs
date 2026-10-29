//! Bounded live measurements against static-ct-api logs.
//!
//! ```text
//! ct-tiles-watch consistency --log <description> [--n 6] [--interval-s 30] [--earlier SIZE:ROOT_B64] --out F
//! ct-tiles-watch catchup     --log <description> [--tiles 32] [--budget-s 120] --out F
//! ct-tiles-watch detect      --domains a,b,c [--per-domain 5] [--max-der 12] [--negative d] --out F
//! ct-tiles-watch fixture     --log <description> --dir D
//! ```

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ct_tiles_watch::checkpoint::{self, Checkpoint};
use ct_tiles_watch::fixture::Recorder;
use ct_tiles_watch::leaf::{self, Entry};
use ct_tiles_watch::logs::{self, Log};
use ct_tiles_watch::merkle::Hash;
use ct_tiles_watch::net::{Http, HttpTiles};
use ct_tiles_watch::tiles::{self, TileSource, TreeView, WIDTH};
use ct_tiles_watch::{names, sct};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

struct Args(Vec<String>);
impl Args {
    fn get(&self, k: &str) -> Option<String> {
        self.0
            .iter()
            .position(|a| a == k)
            .and_then(|i| self.0.get(i + 1).cloned())
    }
    fn num(&self, k: &str, d: u64) -> u64 {
        self.get(k).map(|v| v.parse().expect("number")).unwrap_or(d)
    }
}

fn find_log<'a>(list: &'a logs::LogList, d: &str) -> &'a Log {
    list.by_description(d)
        .unwrap_or_else(|| panic!("log {d:?} not in logs.json"))
}

fn fetch_checkpoint(http: &Http, log: &Log) -> Result<Checkpoint, String> {
    let b = http.get(&format!("{}checkpoint", log.monitoring_url), 3)?;
    let s = String::from_utf8(b).map_err(|_| "checkpoint is not UTF-8")?;
    checkpoint::verify(&s, &log.key())
}

fn b64(h: &Hash) -> String {
    STANDARD.encode(h)
}

fn write(out: &str, v: &Value) {
    std::fs::write(out, serde_json::to_string_pretty(v).unwrap() + "\n").expect("write output");
    eprintln!("wrote {out}");
}

/// Data tile `index` of a tree of `size`, checked against authenticated
/// level-0 hashes. Falls back to the full tile if the partial one is gone.
fn data_tile<S: TileSource>(
    src: &S,
    view: &mut TreeView<S>,
    index: u64,
) -> Result<(Vec<Entry>, Vec<u8>), String> {
    let w = tiles::tile_width(view.size, 0, index);
    let hashes = view.leaf_hashes(index)?;
    let raw = match src.get(&tiles::data_tile_path(index, w)) {
        Ok(b) => b,
        Err(e) if w < WIDTH => src
            .get(&tiles::data_tile_path(index, WIDTH))
            .map_err(|_| e)?,
        Err(e) => return Err(e),
    };
    let mut entries = leaf::parse_data_tile(&raw)?;
    entries.truncate(w as usize);
    leaf::check_against(&entries, &hashes, index * WIDTH)?;
    Ok((entries, raw))
}

fn consistency(a: &Args) {
    let list = logs::pinned();
    let log = find_log(&list, &a.get("--log").expect("--log"));
    let n = a.num("--n", 6);
    let interval = a.num("--interval-s", 30);
    let http = Http::new(
        Duration::from_secs(30),
        Some(Duration::from_secs(n * interval + 300)),
        50 << 20,
    );
    let src = HttpTiles {
        http: &http,
        prefix: log.monitoring_url.clone(),
    };
    let mut cps: Vec<Checkpoint> = Vec::new();
    let mut fetched_at = Vec::new();
    for i in 0..n {
        if i > 0 {
            std::thread::sleep(Duration::from_secs(interval));
        }
        match fetch_checkpoint(&http, log) {
            Ok(c) => {
                eprintln!("checkpoint size {} root {}", c.size, b64(&c.root));
                fetched_at.push(now_ms());
                cps.push(c);
            }
            Err(e) => eprintln!("checkpoint fetch/verify failed: {e}"),
        }
    }
    let mut pairs = Vec::new();
    let mut ok_pairs = 0;
    for w in cps.windows(2) {
        let (old, new) = (&w[0], &w[1]);
        let t = Instant::now();
        let b0 = http.bytes.get();
        let mut view = TreeView::new(new.size, new.root, &src);
        let r = if new.size < old.size {
            Err("tree shrank".to_string())
        } else {
            view.consistent_with(old.size, &old.root)
        };
        if r.is_ok() {
            ok_pairs += 1;
        }
        pairs.push(json!({
            "old_size": old.size, "new_size": new.size, "growth": new.size - old.size.min(new.size),
            "consistent": r.is_ok(), "error": r.err(), "tiles_fetched": view.tiles_fetched(),
            "bytes": http.bytes.get() - b0, "ms": t.elapsed().as_millis() as u64,
        }));
    }
    let last = cps.last().expect("no checkpoint could be fetched").clone();
    let first = cps.first().unwrap().clone();
    // Earlier observation (from a previous session) against the latest tree.
    let earlier = a.get("--earlier").map(|e| {
        let (s, r) = e.split_once(':').expect("SIZE:ROOT");
        let size: u64 = s.parse().unwrap();
        let root: Hash = STANDARD.decode(r).unwrap().try_into().unwrap();
        let mut view = TreeView::new(last.size, last.root, &src);
        let res = view.consistent_with(size, &root);
        json!({"size": size, "root": r, "consistent_with_latest": res.is_ok(), "error": res.err(),
               "tiles_fetched": view.tiles_fetched()})
    });
    // Negative controls.
    let mut bad_root = first.root;
    bad_root[31] ^= 1;
    let mut view = TreeView::new(last.size, last.root, &src);
    let tampered_root_rejected = if first.size < last.size {
        Some(view.consistent_with(first.size, &bad_root).is_err())
    } else {
        None
    };
    let mut forged = last.root;
    forged[0] ^= 1;
    let lines: Vec<&str> = last.raw.splitn(4, '\n').collect();
    let tampered_note = format!("{}\n{}\n{}\n{}", lines[0], lines[1], b64(&forged), lines[3]);
    let tampered_note_rejected = checkpoint::verify(&tampered_note, &log.key()).is_err();
    let mut view = TreeView::new(last.size, forged, &src);
    let forged_root_rejected_by_tiles = view.verify_root().is_err();
    let other = list
        .tiled_logs
        .iter()
        .find(|l| l.origin != log.origin)
        .unwrap();
    let wrong_key_rejected = checkpoint::verify(&last.raw, &other.key()).is_err();
    let span_ms = last.timestamp_ms.saturating_sub(first.timestamp_ms);
    write(
        &a.get("--out").expect("--out"),
        &json!({
            "log": log.description, "origin": log.origin, "monitoring_url": log.monitoring_url,
            "started_unix_ms": fetched_at.first(), "n_requested": n, "interval_s": interval,
            "checkpoints": cps.iter().zip(&fetched_at).map(|(c, f)| json!({
                "size": c.size, "root": b64(&c.root), "timestamp_ms": c.timestamp_ms, "fetched_unix_ms": f
            })).collect::<Vec<_>>(),
            "pairs": pairs, "pairs_consistent": ok_pairs, "pairs_total": cps.len().saturating_sub(1),
            "growth_entries_per_s": if span_ms > 0 { Some((last.size - first.size) as f64 / (span_ms as f64 / 1000.0)) } else { None },
            "earlier": earlier,
            "controls": {
                "tampered_old_root_rejected": tampered_root_rejected,
                "tampered_note_rejected": tampered_note_rejected,
                "forged_root_rejected_by_tiles": forged_root_rejected_by_tiles,
                "wrong_log_key_rejected": wrong_key_rejected,
            },
            "http": {"requests": http.requests.get(), "bytes": http.bytes.get(), "errors": *http.errors.borrow()},
        }),
    );
}

fn catchup(a: &Args) {
    let list = logs::pinned();
    let log = find_log(&list, &a.get("--log").expect("--log"));
    let k = a.num("--tiles", 32);
    let budget = a.num("--budget-s", 120);
    let http = Http::new(
        Duration::from_secs(30),
        Some(Duration::from_secs(budget)),
        200 << 20,
    );
    let src = HttpTiles {
        http: &http,
        prefix: log.monitoring_url.clone(),
    };
    let cp0 = fetch_checkpoint(&http, log).expect("checkpoint");
    let t0 = Instant::now();
    let mut view = TreeView::new(cp0.size, cp0.root, &src);
    view.verify_root().expect("root from tiles");
    let full = cp0.size / WIDTH;
    let first = full.saturating_sub(k);
    let (mut entries_n, mut precerts, mut names_n, mut name_errors, mut done) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut errors = Vec::new();
    let mut tampered_rejected = None;
    let mut stopped = None;
    for idx in first..full {
        if t0.elapsed() > Duration::from_secs(budget) {
            stopped = Some("time budget");
            break;
        }
        match data_tile(&src, &mut view, idx) {
            Ok((es, raw)) => {
                done += 1;
                for e in &es {
                    entries_n += 1;
                    if e.entry_type == leaf::EntryType::Precert {
                        precerts += 1;
                    }
                    match names::names(e) {
                        Ok(v) => names_n += v.len() as u64,
                        Err(_) => name_errors += 1,
                    }
                }
                if tampered_rejected.is_none() {
                    // Flip one byte in the middle of the raw tile: it must not verify.
                    let mut bad = raw.clone();
                    let mid = bad.len() / 2;
                    bad[mid] ^= 1;
                    let hashes = view.leaf_hashes(idx).unwrap();
                    tampered_rejected = Some(
                        leaf::parse_data_tile(&bad)
                            .and_then(|es| leaf::check_against(&es, &hashes, idx * WIDTH))
                            .is_err(),
                    );
                }
            }
            Err(e) => {
                errors.push(format!("tile {idx}: {e}"));
                if e.contains("budget") {
                    stopped = Some("budget");
                    break;
                }
            }
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    let cp1 = fetch_checkpoint(&http, log).ok();
    let growth = cp1.as_ref().and_then(|c| {
        let dt = c.timestamp_ms.saturating_sub(cp0.timestamp_ms) as f64 / 1000.0;
        (dt > 0.0).then(|| (c.size - cp0.size) as f64 / dt)
    });
    let rate = entries_n as f64 / secs;
    write(
        &a.get("--out").expect("--out"),
        &json!({
            "log": log.description, "monitoring_url": log.monitoring_url, "started_unix_ms": now_ms(),
            "checkpoint": {"size": cp0.size, "root": b64(&cp0.root)},
            "tiles_requested": k, "tiles_done": done, "first_tile": first, "budget_s": budget, "stopped": stopped,
            "entries": entries_n, "precert_entries": precerts, "dns_names": names_n, "name_parse_errors": name_errors,
            "wall_s": secs, "entries_per_s": rate,
            "http": {"requests": http.requests.get(), "bytes_decoded": http.bytes.get(), "errors": *http.errors.borrow()},
            "growth_entries_per_s": growth,
            "derived": {
                "note": "derived from the measured rate; sequential single connection; not measured end to end",
                "throughput_over_growth": growth.map(|g| rate / g),
                "hours_to_read_whole_log": rate.recip() * cp0.size as f64 / 3600.0,
                "seconds_to_absorb_one_hour_of_growth": growth.map(|g| g * 3600.0 / rate),
            },
            "controls": {"tampered_entry_rejected": tampered_rejected},
            "errors": errors,
        }),
    );
}

fn crtsh_ids(http: &Http, domain: &str) -> Result<Vec<(u64, String)>, String> {
    let url = format!("https://crt.sh/?q={domain}&output=json&exclude=expired");
    let b = http.get(&url, 3)?;
    let v: Value = serde_json::from_slice(&b).map_err(|e| format!("crt.sh JSON: {e}"))?;
    let mut ids: Vec<(u64, String)> = v
        .as_array()
        .ok_or("crt.sh: not an array")?
        .iter()
        .filter_map(|r| Some((r["id"].as_u64()?, r["serial_number"].as_str()?.to_string())))
        .collect();
    ids.sort();
    ids.dedup();
    ids.reverse();
    Ok(ids)
}

fn detect(a: &Args) {
    let list = logs::pinned();
    let domains: Vec<String> = a
        .get("--domains")
        .expect("--domains")
        .split(',')
        .map(String::from)
        .collect();
    let per = a.num("--per-domain", 5) as usize;
    let max_der = a.num("--max-der", 12) as usize;
    let crt = Http::new(
        Duration::from_secs(45),
        Some(Duration::from_secs(1500)),
        50 << 20,
    );
    let ct = Http::new(
        Duration::from_secs(30),
        Some(Duration::from_secs(1500)),
        100 << 20,
    );
    let mut cps: HashMap<String, Checkpoint> = HashMap::new();
    let mut rows = Vec::new();
    let mut per_domain = Vec::new();
    let mut crtsh_failures = Vec::new();
    for d in &domains {
        std::thread::sleep(Duration::from_secs(3));
        let ids = match crtsh_ids(&crt, d) {
            Ok(v) => v,
            Err(e) => {
                crtsh_failures.push(json!({"domain": d, "stage": "query", "error": e}));
                per_domain.push(json!({"domain": d, "crtsh": "failed"}));
                continue;
            }
        };
        let (mut der_tried, mut der_failed, mut no_tiled, mut candidates, mut detected) =
            (0, 0, 0, 0, 0);
        for (id, _) in &ids {
            if candidates >= per || der_tried >= max_der {
                break;
            }
            der_tried += 1;
            std::thread::sleep(Duration::from_secs(1));
            let der = match crt
                .get(&format!("https://crt.sh/?d={id}"), 4)
                .and_then(|b| sct::to_der(&b))
            {
                Ok(b) => b,
                Err(e) => {
                    der_failed += 1;
                    crtsh_failures.push(json!({"domain": d, "stage": "der", "id": id, "error": e}));
                    continue;
                }
            };
            let Ok(scts) = sct::embedded(&der) else {
                der_failed += 1;
                continue;
            };
            let tiled: Vec<_> = scts
                .iter()
                .filter_map(|s| Some((s, list.by_log_id(&s.log_id)?)))
                .filter(|(s, _)| s.leaf_index.is_some())
                .collect();
            if tiled.is_empty() {
                no_tiled += 1; // precertificate (no SCTs) or only non-tiled logs
                continue;
            }
            candidates += 1;
            let serial = sct::serial(&der).unwrap();
            let (s, log) = tiled[0];
            let li = s.leaf_index.unwrap();
            let cp = match cps.get(&log.origin) {
                Some(c) => Ok(c.clone()),
                None => fetch_checkpoint(&ct, log).inspect(|c| {
                    cps.insert(log.origin.clone(), c.clone());
                }),
            };
            let src = HttpTiles {
                http: &ct,
                prefix: log.monitoring_url.clone(),
            };
            let res: Result<Value, String> = cp.and_then(|cp| {
                if li >= cp.size {
                    return Err("leaf_index beyond checkpoint".into());
                }
                let mut view = TreeView::new(cp.size, cp.root, &src);
                let (es, _) = data_tile(&src, &mut view, li / WIDTH)?;
                let e = &es[(li % WIDTH) as usize];
                let ns = names::names(e)?;
                let ts_ok = e.timestamp_ms == s.timestamp_ms;
                let serial_ok = names::serial(e)? == serial;
                let filter_hit = ns.iter().any(|n| names::matches(n, d));
                let lookalike = format!("x{d}");
                let lookalike_hit = ns.iter().any(|n| names::matches(n, &lookalike));
                let neighbour = &es[((li % WIDTH) as usize + 1) % es.len()];
                let neighbour_matches = neighbour.timestamp_ms == s.timestamp_ms
                    && names::serial(neighbour).map(|x| x == serial).unwrap_or(false);
                Ok(json!({
                    "timestamp_match": ts_ok, "serial_match": serial_ok, "leaf_index_ext_match": e.leaf_index_ext == Some(li),
                    "san_filter_hit": filter_hit, "lookalike_filter_hit": lookalike_hit,
                    "neighbour_entry_matches": neighbour_matches, "names": ns.len(),
                }))
            });
            let hit = res
                .as_ref()
                .map(|v| {
                    v["timestamp_match"] == true
                        && v["serial_match"] == true
                        && v["leaf_index_ext_match"] == true
                        && v["san_filter_hit"] == true
                })
                .unwrap_or(false);
            if hit {
                detected += 1;
            }
            rows.push(json!({"domain": d, "crtsh_id": id, "log": log.description, "leaf_index": li,
                             "detected": hit, "check": res.as_ref().ok(), "error": res.as_ref().err()}));
        }
        per_domain.push(json!({"domain": d, "crtsh_unexpired_ids": ids.len(), "der_tried": der_tried,
            "der_failed": der_failed, "no_tiled_sct": no_tiled, "candidates": candidates, "detected": detected}));
    }
    let mut negatives = Vec::new();
    if let Some(n) = a.get("--negative") {
        for d in n.split(',') {
            std::thread::sleep(Duration::from_secs(3));
            let r = crtsh_ids(&crt, d);
            negatives.push(json!({"domain": d, "crtsh_ids": r.as_ref().map(|v| v.len()).ok(), "error": r.err()}));
        }
    }
    let cand: usize = rows.len();
    let det = rows.iter().filter(|r| r["detected"] == true).count();
    write(
        &a.get("--out").expect("--out"),
        &json!({
            "started_unix_ms": now_ms(), "domains": domains, "per_domain_cap": per, "der_cap": max_der,
            "candidates": cand, "detected": det,
            "detected_pct": if cand > 0 { Some(100.0 * det as f64 / cand as f64) } else { None },
            "lookalike_false_hits": rows.iter().filter(|r| r["check"]["lookalike_filter_hit"] == true).count(),
            "neighbour_false_matches": rows.iter().filter(|r| r["check"]["neighbour_entry_matches"] == true).count(),
            "per_domain": per_domain, "rows": rows, "negative_domains": negatives,
            "checkpoints": cps.iter().map(|(o, c)| json!({"origin": o, "size": c.size, "root": b64(&c.root)})).collect::<Vec<_>>(),
            "crtsh_failures": crtsh_failures,
            "http": {"crtsh_requests": crt.requests.get(), "crtsh_bytes": crt.bytes.get(),
                     "ct_requests": ct.requests.get(), "ct_bytes": ct.bytes.get()},
        }),
    );
}

fn fixture(a: &Args) {
    let list = logs::pinned();
    let log = find_log(&list, &a.get("--log").expect("--log"));
    let dir = std::path::PathBuf::from(a.get("--dir").expect("--dir"));
    let http = Http::new(
        Duration::from_secs(30),
        Some(Duration::from_secs(120)),
        20 << 20,
    );
    let src = HttpTiles {
        http: &http,
        prefix: log.monitoring_url.clone(),
    };
    let raw = http
        .get(&format!("{}checkpoint", log.monitoring_url), 3)
        .expect("checkpoint");
    let cp = checkpoint::verify(std::str::from_utf8(&raw).unwrap(), &log.key()).expect("verify");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("checkpoint"), &raw).unwrap();
    let rec = Recorder {
        inner: &src,
        dir: dir.clone(),
        paths: Default::default(),
    };
    let mut view = TreeView::new(cp.size, cp.root, &rec);
    let idx = cp.size / WIDTH - 1;
    data_tile(&rec, &mut view, idx).expect("data tile");
    eprintln!("size {} tile {idx}: {:?}", cp.size, rec.paths.borrow());
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let a = Args(argv.clone());
    match argv.first().map(String::as_str) {
        Some("consistency") => consistency(&a),
        Some("catchup") => catchup(&a),
        Some("detect") => detect(&a),
        Some("fixture") => fixture(&a),
        _ => {
            eprintln!("usage: ct-tiles-watch consistency|catchup|detect|fixture ...");
            std::process::exit(2);
        }
    }
}
