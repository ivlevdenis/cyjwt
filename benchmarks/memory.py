"""Memory probe: cyjwt vs PyJWT in isolated processes.

Measures, per variant:

- import footprint: PSS/RSS delta over a process that imports the library;
- steady state: PSS growth after ``n`` decode/encode calls (leak check);
- transient Python heap peak during the workload (``tracemalloc``);
- peak RSS (``VmHWM``) above the pre-import baseline.

PSS and RSS come from ``/proc/self/smaps_rollup``; PSS is the fair metric when
shared pages (libpython, ``cryptography``'s native modules) are mapped by
several processes.

Both cyjwt and PyJWT import ``cryptography`` eagerly when it is installed, so
run the probe once per environment to get both sets of numbers:

    python benchmarks/memory.py
    python benchmarks/memory.py --python /path/to/venv-without-crypto/bin/python
    python benchmarks/memory.py --markdown        # tables for docs/benchmarks.md

Prints only; writes no files.
"""

from __future__ import annotations

import argparse
import gc
import json
import subprocess
import sys
import tracemalloc
from collections import defaultdict
from typing import Any

SECRET = "0123456789abcdef" * 4
CLAIMS = {"sub": "1234567890", "name": "John Doe", "admin": True, "iat": 1516239022}


def _status() -> dict[str, int]:
    out: dict[str, int] = {}
    with open("/proc/self/smaps_rollup", encoding="ascii") as fh:
        for line in fh:
            if line.startswith("Pss:"):
                out["pss_kb"] = int(line.split()[1])
            elif line.startswith("Rss:"):
                out["rss_kb"] = int(line.split()[1])
    with open("/proc/self/status", encoding="ascii") as fh:
        for line in fh:
            if line.startswith("VmHWM:"):
                out["hwm_kb"] = int(line.split()[1])
    return out


def _versions() -> dict[str, str | None]:
    import cyjwt

    versions: dict[str, str | None] = {"cyjwt": cyjwt.__version__}
    try:
        import jwt as pyjwt

        versions["pyjwt"] = pyjwt.__version__
    except ModuleNotFoundError:  # pragma: no cover - dev convenience
        versions["pyjwt"] = None
    try:
        import cryptography

        versions["cryptography"] = cryptography.__version__
    except ModuleNotFoundError:  # pragma: no cover
        versions["cryptography"] = None
    return versions


def run_child(variant: str, mode: str, n: int) -> None:
    gc.collect()
    base = _status()

    payload = CLAIMS
    token = None
    key = SECRET
    lib: Any = None
    if variant == "cyjwt":
        import cyjwt as lib

        token = lib.encode(CLAIMS, SECRET)
    elif variant == "pyjwt":
        import jwt as lib

        token = lib.encode(CLAIMS, SECRET)

    gc.collect()
    after_import = _status()

    tracemalloc.start()
    for _ in range(n):
        if mode == "decode" and lib is not None:
            lib.decode(token, key, algorithms=["HS256"])
        elif mode == "encode" and lib is not None:
            lib.encode(payload, key)
    traced_peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()

    gc.collect()
    after_work = _status()
    print(
        json.dumps(
            {
                "variant": variant,
                "mode": mode,
                "n": n,
                "import_pss_kb": after_import["pss_kb"] - base["pss_kb"],
                "import_rss_kb": after_import["rss_kb"] - base["rss_kb"],
                "work_pss_kb": after_work["pss_kb"] - after_import["pss_kb"],
                "peak_over_base_kb": after_work["hwm_kb"] - base["hwm_kb"],
                "traced_peak_kb": traced_peak // 1024,
                "modules": len(sys.modules),
                "versions": _versions(),
            }
        )
    )


def collect(python: str, repeats: int, n: int, workload: bool) -> list[dict[str, Any]]:
    cases = [("none", "idle")]
    for variant in ("cyjwt", "pyjwt"):
        cases.append((variant, "idle"))
        if workload:
            cases += [(variant, "decode"), (variant, "encode")]

    rows: list[dict[str, Any]] = []
    for _ in range(repeats):
        for variant, mode in cases:
            proc = subprocess.run(
                [
                    python,
                    __file__,
                    "--child",
                    "--variant",
                    variant,
                    "--mode",
                    mode,
                    "--n",
                    str(n),
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            rows.append(json.loads(proc.stdout.strip().splitlines()[-1]))
    return rows


def aggregate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["variant"], row["mode"])].append(row)

    summary = []
    for (variant, mode), group in sorted(grouped.items()):
        summary.append(
            {
                "variant": variant,
                "mode": mode,
                "import_pss_kb": min(r["import_pss_kb"] for r in group),
                "import_rss_kb": min(r["import_rss_kb"] for r in group),
                "work_pss_kb": min(r["work_pss_kb"] for r in group),
                "peak_over_base_kb": min(r["peak_over_base_kb"] for r in group),
                "traced_peak_kb": min(r["traced_peak_kb"] for r in group),
                "modules": group[0]["modules"],
                "versions": group[0]["versions"],
            }
        )
    return summary


def _fmt_kb(value: int) -> str:
    return f"{value:,}".replace(",", " ") + " KB"


def print_report(summary: list[dict[str, Any]], repeats: int, n: int, markdown: bool) -> None:
    versions = summary[0]["versions"]
    env = (
        f"cyJWT {versions['cyjwt']}, PyJWT {versions['pyjwt']}, "
        f"cryptography {versions['cryptography'] or 'not installed'}, "
        f"Python {sys.version.split()[0]}"
    )
    heading = f"repeats={repeats}, n={n}, min over repeats; {env}"
    if not markdown:
        print(heading)
        print(
            f"{'variant':8} {'mode':7} {'import PSS':>11} {'import RSS':>11} "
            f"{'work PSS':>9} {'peak RSS':>10} {'traced':>8} {'modules':>7}"
        )
        for row in summary:
            print(
                f"{row['variant']:8} {row['mode']:7} "
                f"{_fmt_kb(row['import_pss_kb']):>11} {_fmt_kb(row['import_rss_kb']):>11} "
                f"{_fmt_kb(row['work_pss_kb']):>9} {_fmt_kb(row['peak_over_base_kb']):>10} "
                f"{_fmt_kb(row['traced_peak_kb']):>8} {row['modules']:>7}"
            )
        return

    print(f"_{heading}._\n")
    print(
        "| Variant | Mode | Import ΔPSS | Import ΔRSS | Steady-state ΔPSS "
        "| Peak RSS over baseline | Python heap peak |"
    )
    print("|---|---|---:|---:|---:|---:|---:|")
    for row in summary:
        print(
            f"| `{row['variant']}` | {row['mode']} | {_fmt_kb(row['import_pss_kb'])} "
            f"| {_fmt_kb(row['import_rss_kb'])} | {_fmt_kb(row['work_pss_kb'])} "
            f"| {_fmt_kb(row['peak_over_base_kb'])} | {_fmt_kb(row['traced_peak_kb'])} |"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--variant", choices=["none", "cyjwt", "pyjwt"], default="none")
    parser.add_argument("--mode", choices=["idle", "decode", "encode"], default="idle")
    parser.add_argument("--n", type=int, default=50_000)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--python", default=sys.executable, help="interpreter for probes")
    parser.add_argument("--no-workload", action="store_true", help="import footprint only")
    parser.add_argument("--markdown", action="store_true", help="emit Markdown tables")
    args = parser.parse_args(argv)

    if args.child:
        run_child(args.variant, args.mode, args.n)
        return 0

    rows = collect(args.python, args.repeats, args.n, not args.no_workload)
    print_report(aggregate(rows), args.repeats, args.n, args.markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
