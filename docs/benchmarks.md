# Benchmarks

`cyjwt` is a drop-in replacement for [PyJWT](https://github.com/jpadilla/pyjwt),
so every number below is a same-session comparison against PyJWT 2.15.1 running
the identical call on the identical token. PyJWT is the `1.00` baseline on all
charts; bars show cyjwt's ratio to it, then the absolute throughput.

![cyjwt vs PyJWT](img/charts/bench-cyjwt-vs-pyjwt.svg)

## Method

- **Timing:** `timeit.Timer.autorange()` calibrates the iteration count for
  every series, then 3 rounds are taken with the series order alternated
  (cyjwt → PyJWT, then PyJWT → cyjwt) to spread machine drift. The best round
  wins. One process, no concurrency; numbers are throughput per call, not
  end-to-end HTTP.
- **Tokens** are created once per stage, outside the timed loop; encode and
  decode are timed separately.
- **Asymmetric stages use already-loaded `cryptography` key objects.** PEM
  parsing is excluded on purpose: `load_pem_private_key` validates the key
  (primality checks for RSA) and costs milliseconds per call, which would
  swamp everything else. See the [key parsing](#key-parsing-is-not-timed) note.
- **Claims:** `decode-hs256-claims` also validates `aud`, `iss` and `exp`;
  the other decode stages pass only the algorithm allow-list.
- **Payload sizes:** `small` is 4 claims (~90 bytes of JSON), `1k` adds a
  1024-character string field.
- Results are written to `benchmarks/results/stage-<name>.json` (gitignored);
  charts are regenerated from them and committed under `docs/img/charts/`.

## Environment

| Parameter | Value |
|---|---|
| Python | 3.13.0 |
| cyjwt | 0.2.0 (Cython 3.3.1) |
| PyJWT | 2.15.1 |
| cryptography | 50.0.2 |
| OS / CPU | Ubuntu 26.04 LTS, kernel 7.0.0, x86_64 |

## Results (op/s, higher is better)

| Stage | cyjwt | PyJWT | Speedup |
|---|---:|---:|---:|
| `encode-hs256` | 112,206 | 65,254 | **1.72×** |
| `decode-hs256` | 97,739 | 40,017 | **2.44×** |
| `decode-hs256-claims` | 85,052 | 33,194 | **2.56×** |
| `encode-hs256-1k` | 81,659 | 51,300 | **1.59×** |
| `decode-hs256-1k` | 82,332 | 15,068 | **5.46×** |
| `encode-hs512` | 99,384 | 62,810 | **1.58×** |
| `decode-hs512` | 90,815 | 36,736 | **2.47×** |
| `encode-rs256` | 2,218 | 2,198 | **1.01×** |
| `decode-rs256` | 41,915 | 22,307 | **1.88×** |
| `encode-es256` | 38,377 | 35,902 | **1.07×** |
| `decode-es256` | 16,600 | 13,181 | **1.26×** |
| `encode-eddsa` | 33,292 | 32,033 | **1.04×** |
| `decode-eddsa` | 12,078 | 10,640 | **1.14×** |

### CPU and memory per stage

Every stage also records resource use. CPU time is `process_time()` (user +
system) attributed to each series; both series share one process, so memory is
stage-wide: peak `VmRSS` sampled every 10 ms, plus `RSS` growth and `PSS` after
the stage. A single-threaded Python loop saturates one core, so utilisation is
~100% for both variants; the useful number is CPU time per operation.

| Stage | cyjwt µs CPU/op | PyJWT µs CPU/op | PyJWT / cyjwt |
|---|---:|---:|---:|
| `encode-hs256` | 9.08 | 15.48 | 1.71× |
| `decode-hs256` | 10.38 | 25.20 | 2.43× |
| `decode-hs256-claims` | 12.12 | 30.72 | 2.54× |
| `encode-hs256-1k` | 12.41 | 19.93 | 1.61× |
| `decode-hs256-1k` | 12.50 | 67.53 | 5.40× |
| `encode-hs512` | 10.28 | 16.26 | 1.58× |
| `decode-hs512` | 11.29 | 27.72 | 2.45× |
| `encode-rs256` | 456.55 | 459.92 | 1.01× |
| `decode-rs256` | 24.04 | 44.89 | 1.87× |
| `encode-es256` | 27.34 | 28.91 | 1.06× |
| `decode-es256` | 64.44 | 77.29 | 1.20× |
| `encode-eddsa` | 31.02 | 32.07 | 1.03× |
| `decode-eddsa` | 84.13 | 95.49 | 1.14× |

Peak RSS stays at 36.9-37.1 MB for every stage (interpreter + `cryptography`
import dominates), and RSS growth during a stage is at most 72 KB, i.e. the
allocator reaches steady state with no per-stage leak. Raw numbers are in
`benchmarks/results/stage-*.json` (`resources` object). Charts:
[bench-cpu-time.svg](img/charts/bench-cpu-time.svg) and
[bench-memory.svg](img/charts/bench-memory.svg).

## Where the difference comes from

- **HS decode, small payload (2.48×):** the Cython core decodes and validates
  base64url in one C loop, splits the compact token in one pass, and compares
  the HMAC in constant time without Python objects. PyJWT additionally runs a
  per-character Python loop over every base64url segment.
- **HS decode, ~1 KB payload (5.46×):** that per-character loop is O(payload
  length) in Python, while ours stays in C — the gap grows with the token.
- **HS encode (1.6–1.7×):** base64url encoding is table-driven in C, and the
  payload encoder is a cached `json.JSONEncoder` instance; JSON serialization
  itself remains stdlib.
- **RS256 encode (1.00×):** the RSA operation (~400 µs at 2048 bits) dominates
  and is identical in both libraries; only Python-layer overhead differs.
- **ES256 / EdDSA (1.04–1.26×):** the signature/verification cost is
  `cryptography`'s, so the gain is limited to token parsing and JSON.
- **RS256 decode (1.88×):** verification is ~21 µs, so the fixed Python-layer
  savings are visible.

## Key parsing is not timed

`prepare_key` parses PEM on every `encode`/`decode` when a PEM string is
passed. For RSA **private** keys that parse runs OpenSSL key validation and
costs milliseconds, not microseconds (measured on this host with
`cryptography` 50):

| Key size | `load_pem_private_key` per call | `prepare_key(key object)` |
|---|---:|---:|
| 2048 | 24.9 ms | 0.50 µs |
| 3072 | 78.0 ms | 0.52 µs |
| 4096 | 179.7 ms | 0.50 µs |

With a PEM string, `encode` is ~25.8 ms at 2048 bits instead of 417 µs
(61× slower) — for both cyjwt and PyJWT. Load the key once at startup and pass
the `cryptography` object; public PEM keys parse in 7–9 µs, so `decode` is much
less affected.

## Memory

Measured by `benchmarks/memory.py`: every case runs in a fresh subprocess, so
imports of the probe itself do not leak into the numbers. PSS and RSS come from
`/proc/self/smaps_rollup` (PSS counts shared pages once), `n = 50,000`
decode/encode calls per case, minimum over 3 repeats, and the Python heap peak
is `tracemalloc`'s peak during the loop.

Both libraries import `cryptography` eagerly when it is installed, so the
tables are split by environment; compare rows within a table, not across
sessions.

### With `cryptography` installed

| Variant | Mode | Import ΔPSS | Import ΔRSS | Steady-state ΔPSS | Peak RSS over baseline | Python heap peak |
|---|---|---:|---:|---:|---:|---:|
| `cyjwt` | decode | 13 141 KB | 16 928 KB | 7 KB | 16 928 KB | 11 KB |
| `cyjwt` | encode | 13 132 KB | 16 852 KB | 0 KB | 16 852 KB | 1 KB |
| `pyjwt` | decode | 15 700 KB | 19 688 KB | 24 KB | 19 712 KB | 35 KB |
| `pyjwt` | encode | 15 706 KB | 19 688 KB | 8 KB | 19 696 KB | 16 KB |

### Without `cryptography` (HMAC only)

| Variant | Mode | Import ΔPSS | Import ΔRSS | Steady-state ΔPSS | Peak RSS over baseline | Python heap peak |
|---|---|---:|---:|---:|---:|---:|
| `cyjwt` | decode | 1 709 KB | 5 320 KB | 16 KB | 5 344 KB | 11 KB |
| `cyjwt` | encode | 1 709 KB | 5 320 KB | 4 KB | 5 324 KB | 1 KB |
| `pyjwt` | decode | 5 228 KB | 9 096 KB | 60 KB | 9 160 KB | 33 KB |
| `pyjwt` | encode | 5 229 KB | 9 088 KB | 16 KB | 9 108 KB | 21 KB |

What the numbers say:

- With `cryptography` installed, it dominates the import footprint in both
  cases (~12-13 MB of the deltas); cyjwt still lands ~2.5 MB lower in PSS and
  ~2.8 MB lower in RSS.
- Without it, cyjwt's import is **3.0x lighter in PSS** and **1.7x lighter in
  RSS**: fewer Python modules and no per-module dicts, just one mapped `.so`.
- Steady state is flat for both (tens of KB, allocator slack): no per-call
  retention or leak over 50k operations.
- Transient Python heap per operation is ~3x lower for cyjwt (11 KB vs 35 KB on
  decode, 1 KB vs 16 KB on encode) because more of the work happens in C.

On disk, an uncompressed cyjwt wheel is 629 KB (553 KB of it is `_core*.so`),
PyJWT is 244 KB of pure Python, and `cryptography` adds 15.5 MB when installed.

```bash
python benchmarks/memory.py                 # current environment
python benchmarks/memory.py --markdown      # tables for this document
python benchmarks/memory.py --no-workload   # import footprint only
# second table: run against a venv without cryptography
python benchmarks/memory.py --python /path/to/venv/bin/python --markdown
```

## Charts

| Stage | SVG |
|---|---|
| combined | [bench-cyjwt-vs-pyjwt.svg](img/charts/bench-cyjwt-vs-pyjwt.svg) |
| CPU time per op | [bench-cpu-time.svg](img/charts/bench-cpu-time.svg) |
| memory per stage | [bench-memory.svg](img/charts/bench-memory.svg) |
| `encode-hs256` | [stage-encode-hs256.svg](img/charts/stage-encode-hs256.svg) |
| `decode-hs256` | [stage-decode-hs256.svg](img/charts/stage-decode-hs256.svg) |
| `decode-hs256-claims` | [stage-decode-hs256-claims.svg](img/charts/stage-decode-hs256-claims.svg) |
| `encode-hs256-1k` | [stage-encode-hs256-1k.svg](img/charts/stage-encode-hs256-1k.svg) |
| `decode-hs256-1k` | [stage-decode-hs256-1k.svg](img/charts/stage-decode-hs256-1k.svg) |
| `encode-hs512` | [stage-encode-hs512.svg](img/charts/stage-encode-hs512.svg) |
| `decode-hs512` | [stage-decode-hs512.svg](img/charts/stage-decode-hs512.svg) |
| `encode-rs256` | [stage-encode-rs256.svg](img/charts/stage-encode-rs256.svg) |
| `decode-rs256` | [stage-decode-rs256.svg](img/charts/stage-decode-rs256.svg) |
| `encode-es256` | [stage-encode-es256.svg](img/charts/stage-encode-es256.svg) |
| `decode-es256` | [stage-decode-es256.svg](img/charts/stage-decode-es256.svg) |
| `encode-eddsa` | [stage-encode-eddsa.svg](img/charts/stage-encode-eddsa.svg) |
| `decode-eddsa` | [stage-decode-eddsa.svg](img/charts/stage-decode-eddsa.svg) |

PNG exports (192 dpi) live next to the SVGs when `inkscape` is installed.

## Reproduce

```bash
pip install -e ".[dev]"
python benchmarks/bench.py            # all stages + charts
python benchmarks/bench.py --stages encode-hs256,decode-hs256
python benchmarks/bench.py --rounds 5 --no-charts
python benchmarks/chart.py            # re-render charts from results JSON
python benchmarks/chart.py --check    # layout check into a temp dir
```

`benchmarks/chart.py` uses only the standard library for SVG and shells out to
`inkscape` only for the optional PNG export. Results are not committed; the
charts are.
