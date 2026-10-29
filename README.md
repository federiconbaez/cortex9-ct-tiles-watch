# cortex9-ct-tiles-watch

A small Certificate Transparency **monitor for [static-ct-api](https://c2sp.org/static-ct-api)
(tiled) logs**. It reads checkpoints and tiles over HTTP, authenticates every
tile before use, checks consistency between checkpoints from the tiles
themselves (no proof RPC), filters entries by DNS name, and emits JSON.

This fills the gap left by [`ctclient`](https://crates.io/crates/ctclient)
(RFC 6962 only; last release 2020-07-11) and is a *client*, not a log — unlike
Cloudflare’s [`static_ct_api`](https://crates.io/crates/static_ct_api) crate
(server-side, in [azul](https://github.com/cloudflare/azul)).

Thresholds and the measurement plan were
[pre-registered](PREREGISTRO.md) **before** any live measurement.

## Results (measured)

### 1. Checkpoint consistency — **pass**

| Log | Pairs consistent | Negative controls (4/4) | Earlier observation |
|-----|------------------|-------------------------|---------------------|
| Let's Encrypt Sycamore2026h2 | **5/5** | all rejected as required | size `1047968710` consistent with latest |
| Geomys Tuscolo2026h2 | **5/5** | all rejected as required | size `1025009909` consistent with latest |

Raw: `results/consistency_sycamore2026h2.json`, `results/consistency_tuscolo2026h2.json`.

### 2. Catch-up — **pass** (throughput > growth)

| Log | Tiles | Entries | Wall | Entries/s | Growth/s | Throughput/growth |
|-----|-------|---------|------|-----------|----------|-------------------|
| Sycamore2026h2 | 32 | 8192 | 0.99 s | 8291 | 16.0 | **518×** |
| Tuscolo2026h2 | 8 | 2048 | 2.48 s | 827 | 18.5 | **45×** |

Tampered-entry negative control: rejected on both. Derived whole-log hours are
**not** measured end-to-end (see JSON `derived.note`).

Raw: `results/catchup_sycamore2026h2.json`, `results/catchup_tuscolo2026h2.json`.

### 3. Domain detection vs crt.sh — **missed threshold**

| Metric | Threshold | Measured |
|--------|-----------|----------|
| Candidates detected | ≥ 95 % | **88.2 %** (15/17) |
| Lookalike false hits (`x<domain>`) | 0 | **0** |
| Neighbour false matches | 0 | **0** |
| Negative domain crt.sh ids | 0 | **0** |

crt.sh returned many errors during the run (query 502 / DER 404); those are
counted in `crtsh_failures` (20) and **not** replaced by another source, per
the pre-registration. Domains with a complete crt.sh failure produced **no
candidates** (debian.org, rust-lang.org, gnu.org).

**Declared limit (also in the pre-registration):** this measures that the
reader finds and filters what crt.sh knows, given the SCT `leaf_index`. It is
**not** a full scan of the log for a domain.

Raw: `results/detect.json`.

## Build & test

```bash
cargo test
cargo run --release -- consistency --log "Let's Encrypt Sycamore2026h2" --n 6 --interval-s 30 --out /tmp/c.json
cargo run --release -- catchup --log "Let's Encrypt Sycamore2026h2" --tiles 32 --budget-s 120 --out /tmp/u.json
cargo run --release -- detect --domains debian.org,kernel.org --out /tmp/d.json
```

CI runs `fmt`, `clippy -D warnings`, and offline tests (synthetic trees +
committed public fixtures). Live measurements are **not** in CI (would hammer
production logs and crt.sh).

HTTP clients send a User-Agent with a contact address; Skylight returns **429**
without one.

## What is unverified / out of scope

- Monitoring every CT log at scale, full mirrors, gossip between monitors
- End-to-end time to read an entire multi-hundred-million-entry log
- Detection by scanning the whole log for a domain (we use SCT `leaf_index`)
- Native proof that crt.sh is complete (it is only a control)

## Sources actually read

- https://c2sp.org/static-ct-api
- https://github.com/FiloSottile/sunlight (README + public config)
- https://crates.io/crates/ctclient (updated_at 2020-07-11)
- https://crates.io/crates/static_ct_api (Cloudflare azul)
- Chrome CT log list v3 (`logs.json` pin)
- Live monitoring prefixes: `mon.sycamore.ct.letsencrypt.org`, `tuscolo*.skylight.geomys.org`

## License

Apache-2.0.
