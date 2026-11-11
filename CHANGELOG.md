# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Benchmark stages record CPU utilisation and CPU time per operation per series,
  plus peak RSS (10 ms sampler), RSS growth and PSS after every stage; the data
  is written to `benchmarks/results/*.json` and tabulated in
  `docs/benchmarks.md`.

### Changed

- Relicensed from MIT to Apache License 2.0 (see `LICENSE` and `NOTICE`).

## [0.2.0] - 2026-11-10

### Added

- Optional `crypto` extra (`pip install cyjwt[crypto]`) implementing
  `RS256/384/512`, `PS256/384/512`, `ES256`, `ES256K`, `ES384`, `ES512`,
  `ES521` and `EdDSA` (Ed25519/Ed448) via `cryptography`.
- Key handling for asymmetric algorithms: `cryptography` key objects, PEM
  private/public keys and OpenSSH public keys; per-algorithm curve pinning and
  RSA minimum key-size checks.
- HMAC keys that look like DER/x509 material are rejected, extending the
  existing PEM/SSH/JWK algorithm-confusion guards.
- Benchmark suite (`benchmarks/bench.py`) comparing against PyJWT, an
  stdlib-only SVG/PNG chart renderer (`benchmarks/chart.py`), a memory probe
  (`benchmarks/memory.py`), generated charts in `docs/img/charts/` and the
  methodology in `docs/benchmarks.md`.
- `PyJWT`, `PyJWS`, `register_algorithm`, `get_unverified_header` and the full
  exception hierarchy for the supported algorithms.

### Changed

- `Algorithm` gained `check_key_length` and `check_crypto_key_type`, matching
  PyJWT 2.15 panic-free key validation and `InsecureKeyLengthWarning` behaviour.
- Docs, CI and packaging metadata are ready for a public release.

## [0.1.0] - 2026-11-10

### Added

- Initial implementation: `HS256/HS384/HS512` and `none` with a Cython core
  (base64url, compact-JWS splitting, constant-time HMAC comparison).
- PyJWT 2.15-compatible API surface for the HMAC subset: `encode`, `decode`,
  `decode_complete`, `PyJWT`, `PyJWS`, `crit`/`b64` handling, detached payloads,
  claims validation (`exp`, `nbf`, `iat`, `aud`, `iss`, `sub`, `jti`,
  `require`, `leeway`), key-length warnings and the exception hierarchy.
- Differential test suite against PyJWT, RFC 7515 and jwt.io vectors, and
  support for Python 3.12-3.15.
