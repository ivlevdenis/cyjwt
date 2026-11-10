# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | yes |
| < 0.2 | no |

## Reporting a vulnerability

Please do **not** open a public issue for security reports.

Use GitHub's private vulnerability reporting for this repository
("Security" → "Report a vulnerability"), or email the maintainer at the address
in `pyproject.toml`. Include:

- the affected version and Python/platform,
- a minimal reproducer (token, key shape, call made),
- the impact you expect.

You will get an acknowledgement when the report is triaged. Fixes are released
as a patch version together with a `SECURITY` entry in `CHANGELOG.md`; credit is
given unless you ask otherwise.

## Scope notes

cyjwt verifies signatures and validates claims; it does not protect against
weak application-side secrets. Keep the `algorithms` allow-list hard-coded,
never derive it from the token header (RFC 8725 §2.1), and avoid PEM parsing on
the hot path for RSA private keys (see `docs/benchmarks.md`). The insecure
`none` algorithm is registered for PyJWT compatibility but `verify()` always
returns `False`.
