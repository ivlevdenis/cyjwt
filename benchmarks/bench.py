"""Benchmark runner: cyjwt vs PyJWT.

Measures op/s per stage with ``timeit`` (auto-calibrated iteration counts, best
of N rounds, series order alternated between rounds to spread machine drift).
Alongside throughput it records, per stage, CPU utilisation per series
(``process_time`` over wall time), CPU time per operation, peak RSS sampled
every 10 ms during the stage and PSS after it. Results go to
``benchmarks/results/stage-<name>.json``; charts are re-rendered afterwards.

Usage::

    python benchmarks/bench.py                # full run + charts
    python benchmarks/bench.py --stages encode-hs256,decode-hs256
    python benchmarks/bench.py --rounds 5 --no-charts
"""

from __future__ import annotations

import argparse
import gc
import json
import platform
import sys
import threading
import time
import timeit
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import cyjwt

try:
    import jwt as pyjwt
except ModuleNotFoundError:  # pragma: no cover - benchmark convenience
    pyjwt = None

ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
ROUNDS = 3

SECRET = "0123456789abcdef" * 4
CLAIMS = {"sub": "1234567890", "name": "John Doe", "admin": True, "iat": 1516239022}
CLAIMS_FULL = {
    **CLAIMS,
    "exp": 4102444800,
    "aud": "benchmark",
    "iss": "cyjwt",
}
CLAIMS_1K = {**CLAIMS, "data": "x" * 1024}

Series = dict[str, Callable[[], Any]]


@dataclass(frozen=True)
class Case:
    name: str
    series: Series


def _hmac_cases() -> list[Case]:
    if pyjwt is None:  # pragma: no cover
        raise SystemExit("PyJWT is required for the comparison: pip install pyjwt")

    tokens: dict[str, str] = {}
    for alg, claims in (
        ("HS256", CLAIMS),
        ("HS256-1k", CLAIMS_1K),
        ("HS256-full", CLAIMS_FULL),
        ("HS512", CLAIMS),
    ):
        tokens[alg] = cyjwt.encode(claims, SECRET, algorithm="HS512" if alg == "HS512" else "HS256")

    return [
        Case(
            "encode-hs256",
            {
                "cyjwt": lambda: cyjwt.encode(CLAIMS, SECRET),
                "pyjwt": lambda: pyjwt.encode(CLAIMS, SECRET),
            },
        ),
        Case(
            "decode-hs256",
            {
                "cyjwt": lambda: cyjwt.decode(tokens["HS256"], SECRET, algorithms=["HS256"]),
                "pyjwt": lambda: pyjwt.decode(tokens["HS256"], SECRET, algorithms=["HS256"]),
            },
        ),
        Case(
            "decode-hs256-claims",
            {
                "cyjwt": lambda: cyjwt.decode(
                    tokens["HS256-full"],
                    SECRET,
                    algorithms=["HS256"],
                    audience="benchmark",
                    issuer="cyjwt",
                ),
                "pyjwt": lambda: pyjwt.decode(
                    tokens["HS256-full"],
                    SECRET,
                    algorithms=["HS256"],
                    audience="benchmark",
                    issuer="cyjwt",
                ),
            },
        ),
        Case(
            "encode-hs256-1k",
            {
                "cyjwt": lambda: cyjwt.encode(CLAIMS_1K, SECRET),
                "pyjwt": lambda: pyjwt.encode(CLAIMS_1K, SECRET),
            },
        ),
        Case(
            "decode-hs256-1k",
            {
                "cyjwt": lambda: cyjwt.decode(tokens["HS256-1k"], SECRET, algorithms=["HS256"]),
                "pyjwt": lambda: pyjwt.decode(tokens["HS256-1k"], SECRET, algorithms=["HS256"]),
            },
        ),
        Case(
            "encode-hs512",
            {
                "cyjwt": lambda: cyjwt.encode(CLAIMS, SECRET, algorithm="HS512"),
                "pyjwt": lambda: pyjwt.encode(CLAIMS, SECRET, algorithm="HS512"),
            },
        ),
        Case(
            "decode-hs512",
            {
                "cyjwt": lambda: cyjwt.decode(tokens["HS512"], SECRET, algorithms=["HS512"]),
                "pyjwt": lambda: pyjwt.decode(tokens["HS512"], SECRET, algorithms=["HS512"]),
            },
        ),
    ]


def _asymmetric_cases() -> list[Case]:
    """Sign/verify with already-loaded key objects (PEM parsing excluded)."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    except ModuleNotFoundError:  # pragma: no cover
        print("cryptography is not installed: skipping asymmetric stages", file=sys.stderr)
        return []
    if pyjwt is None:  # pragma: no cover
        return []

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ed_key = ed25519.Ed25519PrivateKey.generate()

    cases: list[Case] = []
    for stage, alg, private, public in (
        ("rs256", "RS256", rsa_key, rsa_key.public_key()),
        ("es256", "ES256", ec_key, ec_key.public_key()),
        ("eddsa", "EdDSA", ed_key, ed_key.public_key()),
    ):
        token = cyjwt.encode(CLAIMS, private, algorithm=alg)
        cases.append(
            Case(
                f"encode-{stage}",
                {
                    "cyjwt": lambda p=private, a=alg: cyjwt.encode(CLAIMS, p, algorithm=a),
                    "pyjwt": lambda p=private, a=alg: pyjwt.encode(CLAIMS, p, algorithm=a),
                },
            )
        )
        cases.append(
            Case(
                f"decode-{stage}",
                {
                    "cyjwt": lambda t=token, k=public, a=alg: cyjwt.decode(t, k, algorithms=[a]),
                    "pyjwt": lambda t=token, k=public, a=alg: pyjwt.decode(t, k, algorithms=[a]),
                },
            )
        )
    return cases


def _rss_kb() -> int:
    with open("/proc/self/status", encoding="ascii") as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    raise RuntimeError("VmRSS is missing from /proc/self/status")


def _pss_kb() -> int:
    with open("/proc/self/smaps_rollup", encoding="ascii") as fh:
        for line in fh:
            if line.startswith("Pss:"):
                return int(line.split()[1])
    raise RuntimeError("Pss is missing from /proc/self/smaps_rollup")


class _RssSampler(threading.Thread):
    """Sample VmRSS in the background and keep the peak for one stage."""

    def __init__(self, interval: float = 0.01) -> None:
        super().__init__(daemon=True)
        self._interval = interval
        self._stopped = threading.Event()
        self.peak_kb = 0

    def run(self) -> None:
        while not self._stopped.is_set():
            self.peak_kb = max(self.peak_kb, _rss_kb())
            self._stopped.wait(self._interval)

    def stop(self) -> int:
        self._stopped.set()
        self.join()
        return self.peak_kb


def measure(series: Series, rounds: int) -> tuple[dict[str, float], dict[str, dict[str, float]]]:
    """Return best op/s per series plus CPU utilisation and CPU time per op.

    Every timed call is wrapped with ``process_time``/``perf_counter`` so CPU
    time is attributed to the series even though their order alternates.
    """
    numbers = {name: timeit.Timer(fn).autorange()[0] for name, fn in series.items()}
    best = dict.fromkeys(series, 0.0)
    cpu_seconds = dict.fromkeys(series, 0.0)
    wall_seconds = dict.fromkeys(series, 0.0)
    operations = dict.fromkeys(series, 0)
    for round_index in range(rounds):
        items = list(series.items())
        if round_index % 2:
            items.reverse()
        for name, fn in items:
            number = numbers[name]
            cpu_before = time.process_time()
            wall_before = time.perf_counter()
            elapsed = timeit.timeit(fn, number=number)
            wall = max(time.perf_counter() - wall_before, elapsed)
            cpu_seconds[name] += time.process_time() - cpu_before
            wall_seconds[name] += wall
            operations[name] += number
            if elapsed > 0:
                best[name] = max(best[name], number / elapsed)

    cpu: dict[str, dict[str, float]] = {}
    for name in series:
        wall = wall_seconds[name]
        ops = operations[name]
        # The stages are single-threaded; the only extra thread is the 10 ms
        # RSS sampler, so a ratio slightly above 1.0 is measurement noise.
        cpu[name] = {
            "pct": min(100.0, 100.0 * cpu_seconds[name] / wall) if wall else 0.0,
            "us_per_op": 1e6 * cpu_seconds[name] / ops if ops else 0.0,
        }
    return best, cpu


def _environment() -> dict[str, str]:
    env = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "cyjwt": cyjwt.__version__,
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    if pyjwt is not None:
        env["pyjwt"] = pyjwt.__version__
    try:
        import cryptography

        env["cryptography"] = cryptography.__version__
    except ModuleNotFoundError:  # pragma: no cover
        pass
    return env


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stages", default="", help="comma-separated stage names")
    parser.add_argument("--rounds", type=int, default=ROUNDS)
    parser.add_argument("--no-charts", action="store_true")
    args = parser.parse_args(argv)

    warnings.simplefilter("ignore")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    for path in RESULTS_DIR.glob("stage-*.json"):
        path.unlink()

    cases = _hmac_cases() + _asymmetric_cases()
    wanted = {s for s in args.stages.split(",") if s}
    if wanted:
        cases = [c for c in cases if c.name in wanted]
        if not cases:
            raise SystemExit(f"no matching stages: {sorted(wanted)}")

    env = _environment()
    print(
        f"python {env['python']}, cyjwt {env['cyjwt']}, pyjwt {env.get('pyjwt')}, "
        f"cryptography {env.get('cryptography', '-')}"
    )
    print(f"rounds={args.rounds}, best op/s per series\n")

    for case in cases:
        started = time.perf_counter()
        gc.collect()
        rss_before = _rss_kb()
        sampler = _RssSampler()
        sampler.start()
        try:
            values, cpu = measure(case.series, args.rounds)
        finally:
            peak_rss = sampler.stop()
        gc.collect()
        resources = {
            "cpu_pct": {name: round(entry["pct"], 1) for name, entry in cpu.items()},
            "cpu_us_per_op": {name: round(entry["us_per_op"], 3) for name, entry in cpu.items()},
            "peak_rss_kb": peak_rss,
            "rss_growth_kb": max(0, peak_rss - rss_before),
            "rss_before_kb": rss_before,
            "rss_after_kb": _rss_kb(),
            "pss_after_kb": _pss_kb(),
        }
        payload = {
            "stage": case.name,
            "values": {k: round(v, 3) for k, v in values.items()},
            "resources": resources,
            "runs": args.rounds,
            "unit": "op/s",
            "environment": env,
        }
        (RESULTS_DIR / f"stage-{case.name}.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
        ratio = values["cyjwt"] / values["pyjwt"] if values.get("pyjwt") else float("nan")
        cpu_text = "/".join(f"{cpu[name]['pct']:.0f}%" for name in values)
        print(
            f"{case.name:20s} cyjwt {values['cyjwt']:12,.0f} op/s   "
            f"pyjwt {values['pyjwt']:12,.0f} op/s   ×{ratio:.2f}   "
            f"cpu {cpu_text}   peak RSS {peak_rss / 1024:.1f} MB   "
            f"({time.perf_counter() - started:.1f}s)"
        )

    if not args.no_charts:
        sys.path.insert(0, str(ROOT))
        import chart

        chart.main([])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
