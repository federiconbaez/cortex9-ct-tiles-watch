# Preregistro / Pre-registration

Escrito y commiteado antes de cualquier medición en vivo. Los fixtures de
tests se capturaron antes, pero no son mediciones. / Written and committed
before any live measurement. Test fixtures were captured earlier but are not
measurements.

## Criterio / Criterion (handoff)

> Lector de tiles static-ct-api contra log real: tiempo de catch-up, % certs de
> dominio de prueba detectados (control crt.sh), consistencia de checkpoints
> consecutivos.

## Logs

- Principal / primary: `Let's Encrypt Sycamore2026h2` (`https://mon.sycamore.ct.letsencrypt.org/2026h2/`).
- Segundo operador / second operator: `Geomys Tuscolo2026h2` (`https://tuscolo2026h2.skylight.geomys.org/`).
- Claves y URLs: `logs.json`, copiado de la lista v3 de Chrome (versión 95.15). / Keys and URLs: `logs.json`, from Chrome's v3 list (version 95.15).

## 1. Consistencia / Consistency

- 6 checkpoints por log, cada 30 s; cada uno con firma RFC 6962 verificada. / 6 checkpoints per log, 30 s apart, each with a verified RFC 6962 signature.
- Cada par consecutivo: raíz del prefijo calculada con tiles autenticados del checkpoint más nuevo == raíz del anterior. / Each consecutive pair: prefix root computed from authenticated tiles of the newer checkpoint == older root.
- Además, observaciones previas contra el último checkpoint / plus earlier observations against the latest checkpoint:
  - Sycamore2026h2 `1047968710:KP8E7hfEP6ciW2s7JRP0lGfYMgThoEhLNXCZQzlOFqU=` y el fixture `1047990054:xZPm6l6/WVQ+pu764xtJy6uAGJRBT+GctFfk1oE/lGE=`.
  - Tuscolo2026h2 `1025009909:m0ViclLQDhwWuQFSTkINI0k9EB86tmx5+WEuHIVo2Qo=`.
- Controles negativos (deben rechazarse) / negative controls (must be rejected): raíz vieja alterada, nota con raíz alterada, raíz falsa contra tiles, clave de otro log. / tampered old root, note with tampered root, forged root against tiles, another log's key.
- Éxito / success: 100 % de pares consistentes y 4/4 controles rechazados. Un par inconsistente se reporta como hallazgo, no se reintenta. / 100 % pairs consistent and 4/4 controls rejected. An inconsistent pair is reported as a finding, not retried.

## 2. Catch-up

- Sycamore2026h2: los últimos 32 data tiles completos (8192 entradas), tope 120 s; Tuscolo2026h2: 8 tiles, tope 60 s. / last 32 full data tiles (8192 entries), 120 s cap; Tuscolo2026h2: 8 tiles, 60 s cap.
- Cada data tile se verifica contra su tile de nivel 0 autenticado y contra leaf_index; se extraen los nombres de cada entrada. / Each data tile is checked against its authenticated level-0 tile and leaf_index; names are extracted from every entry.
- Medido / measured: tiempo de pared, bytes, entradas/s (una conexión, secuencial). Crecimiento del log por checkpoints al inicio y al final. / wall time, bytes, entries/s (one connection, sequential). Log growth from checkpoints at start and end.
- Derivado (no medido de punta a punta) / derived (not measured end to end): cociente throughput/crecimiento, segundos para absorber una hora de crecimiento, horas para leer el log completo.
- Control negativo: un byte alterado en un data tile debe fallar la verificación. / Negative control: one flipped byte in a data tile must fail verification.
- Éxito / success: throughput > crecimiento (cociente > 1). Si hay 429 o se agota el tope, se reporta tal cual. / If 429s happen or the cap runs out, it is reported as is.

## 3. Detección con control crt.sh / Detection with crt.sh control

- Dominios elegidos a priori / domains chosen a priori: `debian.org, kernel.org, archlinux.org, torproject.org, eff.org, python.org, rust-lang.org, gnu.org`.
- Por dominio: consulta JSON de crt.sh (no vencidos), ids más recientes primero, hasta 8 descargas de certificado y hasta 4 candidatos. / Per domain: crt.sh JSON query (unexpired), newest ids first, up to 8 certificate downloads and up to 4 candidates.
- Candidato: certificado final con un SCT de un log tiled de `logs.json` que trae leaf_index. / Candidate: final certificate with an SCT from a tiled log in `logs.json` that carries leaf_index.
- Detectado: la entrada en leaf_index, autenticada contra el checkpoint actual de ese log, tiene el mismo timestamp, el mismo serial, leaf_index igual a su posición y el filtro SAN marca el dominio. / Detected: the entry at leaf_index, authenticated against that log's current checkpoint, has the same timestamp and serial, leaf_index equal to its position, and the SAN filter flags the domain.
- Controles negativos / negative controls: dominio parecido `x<dominio>` no debe marcar; la entrada vecina no debe coincidir; `ct-tiles-watch-nonexistent.invalid` debe dar 0 ids en crt.sh. / lookalike domain must not match; the neighbour entry must not match; the nonexistent domain must return 0 crt.sh ids.
- Éxito / success: ≥ 95 % de candidatos detectados, 0 falsos positivos en controles. Si crt.sh falla o limita, se cuenta y se informa; no se sustituye por otra fuente. / If crt.sh fails or rate-limits, it is counted and reported; no other source is substituted.
- Límite declarado / declared limit: esto mide que el lector encuentra y filtra correctamente lo que crt.sh conoce, dado el índice del SCT. No es un barrido completo del log buscando el dominio. / This measures that the reader finds and filters what crt.sh knows, given the SCT index. It is not a full scan of the log for the domain.
