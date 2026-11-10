# Contributing

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

A C compiler is required to build the Cython extension. `.[dev]` also installs
PyJWT 2.15.1 and `cryptography`, which the differential tests use as a
reference implementation.

## Checks

```bash
pytest                       # includes differential tests against PyJWT
ruff check . && ruff format --check .
mypy                         # strict, src/cyjwt only
```

CI runs the same commands on Python 3.12, 3.13, 3.14 and 3.15, plus a
dependency-free job (no `cryptography`, no PyJWT) that must keep the HMAC paths
working.

## Benchmarks

Benchmarks are part of the repository but are not run in CI:

```bash
python benchmarks/bench.py      # stage results + charts
python benchmarks/memory.py     # import and steady-state memory
```

Raw results stay in `benchmarks/results/` (gitignored); regenerate the charts in
`docs/img/charts/` before committing performance-related changes and update the
tables in `docs/benchmarks.md` if the numbers moved materially.

## Code rules

- Keep `algorithms.py` on the standard library for HMAC; asymmetric algorithms
  live behind the optional `cryptography` import.
- Any change to the public API must stay compatible with PyJWT 2.15 for the
  supported algorithms; add a differential test when you touch it.
- Do not silently drop errors: catch only the expected exception type and
  either handle it meaningfully or re-raise it.
- Update `CHANGELOG.md` for user-visible changes, and bump `_version.py` only in
  release commits.
