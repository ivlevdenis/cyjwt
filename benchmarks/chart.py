"""Chart renderer for the cyjwt benchmarks.

Draws SVG with the standard library only; PNG is exported through ``inkscape``
when it is installed. Reads ``benchmarks/results/stage-*.json`` and writes
``docs/img/charts/stage-<name>.svg`` plus a combined chart.

The layout follows ``ferronit-bench/chart.py``: horizontal bars, the reference
implementation is the ``x1`` baseline, and every bar is followed by its ratio
to the baseline and its absolute value.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "benchmarks" / "results"
CHARTS_DIR = ROOT / "docs" / "img" / "charts"

FONT = "DejaVu Sans, Helvetica, Arial, sans-serif"

# (series id in stage JSON, chart label, colour)
PALETTE: list[tuple[str, str, str]] = [
    ("cyjwt", "cyjwt (Cython core)", "#c0392b"),
    ("pyjwt", "PyJWT 2.15", "#2c3e50"),
]

BASELINE = "pyjwt"
BASELINE_LABEL = "PyJWT"

# Short names for the dense combined chart; the legend keeps the full labels.
SHORT_LABELS = {"cyjwt": "cyjwt", "pyjwt": "PyJWT"}

STAGE_TITLES = {
    "encode-hs256": "HS256 encode — small claims payload",
    "decode-hs256": "HS256 decode — signature only",
    "decode-hs256-claims": "HS256 decode — signature + aud/iss/exp",
    "encode-hs256-1k": "HS256 encode — ~1 KB payload",
    "decode-hs256-1k": "HS256 decode — ~1 KB payload",
    "encode-hs512": "HS512 encode — small claims payload",
    "decode-hs512": "HS512 decode — signature only",
    "encode-rs256": "RS256 encode — key object",
    "decode-rs256": "RS256 decode — key object",
    "encode-es256": "ES256 encode — key object",
    "decode-es256": "ES256 decode — key object",
    "encode-eddsa": "EdDSA (Ed25519) encode — key object",
    "decode-eddsa": "EdDSA (Ed25519) decode — key object",
}

STAGE_ORDER = [
    "encode-hs256",
    "decode-hs256",
    "decode-hs256-claims",
    "encode-hs256-1k",
    "decode-hs256-1k",
    "encode-hs512",
    "decode-hs512",
    "encode-rs256",
    "decode-rs256",
    "encode-es256",
    "decode-es256",
    "encode-eddsa",
    "decode-eddsa",
]

# Label layout, shared by every chart.
LABEL_GAP = 6
RATIO_VALUE_GAP = 12
EDGE_PAD = 14
CHAR_WIDTH = 0.60


def stage_title(stage: str) -> str:
    return STAGE_TITLES.get(stage, stage)


def text_width(text: str, size: float) -> float:
    return len(text) * size * CHAR_WIDTH


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _num(value: float) -> str:
    return f"{value:,.0f}".replace(",", " ")


def _ticks(x_max: float) -> list[float]:
    for step in (0.25, 0.5, 1.0, 2.0, 5.0):
        count = round(x_max / step)
        if count <= 5:
            return [i * step for i in range(count + 1)]
    return [i * 5.0 for i in range(int(x_max / 5.0) + 1)]


def _require_fits(kind: str, label: str, x_end: float, width: float) -> None:
    if x_end > width - 2:
        raise RuntimeError(
            f"{kind} label {label!r} overflows: ends at {x_end:.0f}px, width {width:.0f}px"
        )


def _export_png(svg_path: Path) -> Path | None:
    if shutil.which("inkscape") is None:
        return None
    png = svg_path.with_suffix(".png")
    subprocess.run(
        [
            "inkscape",
            str(svg_path),
            "--export-type=png",
            f"--export-filename={png}",
            "--export-dpi=192",
        ],
        check=False,
        capture_output=True,
    )
    return png if png.exists() else None


def render_stage(
    stage: str,
    values: dict[str, float],
    out_dir: Path,
    *,
    subtitle: str = "same session, best of rounds",
    unit: str = "op/s",
) -> Path:
    """Render one stage as horizontal bars relative to the baseline."""
    apps = [a for a in PALETTE if a[0] in values]
    base = values.get(BASELINE) or max(values.values())
    ratios = {a[0]: values[a[0]] / base for a in apps}
    top = max(ratios.values())
    x_max = max(2.0, round(top * 1.25, 1))

    bar_h, gap = 22, 8
    x0, plot_w = 310, 420
    head, foot = 96, 58
    height = head + len(apps) * (bar_h + gap) - gap + foot
    ratio_font, value_font = 11.5, 11

    def sx(ratio: float) -> float:
        return x0 + ratio / x_max * plot_w

    labels_need = max(
        LABEL_GAP
        + text_width(f"×{ratios[a[0]]:.2f}", ratio_font)
        + RATIO_VALUE_GAP
        + text_width(_num(values[a[0]]), value_font)
        for a in apps
    )
    width = max(
        x0 + plot_w + 60,
        sx(max(ratios.values())) + labels_need + EDGE_PAD,
        44 + text_width(stage_title(stage), 19) + 22,
        44 + text_width(subtitle, 12) + 22,
    )

    out: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="{FONT}">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text x="22" y="34" font-size="19" font-weight="700" fill="#111">'
        f"{_esc(stage_title(stage))}</text>",
        f'<text x="22" y="56" font-size="12" fill="#555">{_esc(subtitle)}</text>',
    ]

    for tick in _ticks(x_max):
        x = sx(tick)
        is_base = abs(tick - 1.0) < 1e-9
        colour = "#c0392b" if is_base else "#ececec"
        dash = ' stroke-dasharray="5 3"' if is_base else ""
        out.append(
            f'<line x1="{x:.1f}" y1="66" x2="{x:.1f}" y2="{height - foot + 4}" '
            f'stroke="{colour}" stroke-width="{1.6 if is_base else 1}"{dash}/>'
        )
        out.append(
            f'<text x="{x:.1f}" y="{height - foot + 20}" font-size="10.5" '
            f'fill="#666" text-anchor="middle">×{tick:g}</text>'
        )

    for i, (app, label, colour) in enumerate(apps):
        y = head + i * (bar_h + gap)
        mid = y + bar_h - 7
        ratio = ratios[app]
        is_base = app == BASELINE
        out.append(f'<rect x="18" y="{y + 5}" width="10" height="10" rx="2" fill="{colour}"/>')
        weight = ' font-weight="700"' if is_base else ""
        out.append(
            f'<text x="34" y="{mid}" font-size="12" fill="#2b2b2b"{weight}>{_esc(label)}</text>'
        )

        end = sx(ratio)
        out.append(
            f'<rect x="{x0}" y="{y}" width="{max(end - x0, 1.5):.1f}" height="{bar_h}" '
            f'rx="3" fill="{colour}"/>'
        )
        fill = "#c0392b" if is_base else "#333"
        ratio_text = f"×{ratio:.2f}"
        x_ratio = end + LABEL_GAP
        x_value = x_ratio + text_width(ratio_text, ratio_font) + RATIO_VALUE_GAP
        out.append(
            f'<text x="{x_ratio:.1f}" y="{mid}" font-size="{ratio_font}" '
            f'fill="{fill}"{weight}>{ratio_text}</text>'
        )
        value_text = _num(values[app])
        out.append(
            f'<text x="{x_value:.1f}" y="{mid}" font-size="{value_font}" '
            f'fill="#666">{value_text}</text>'
        )
        x_after = x_value + text_width(value_text, value_font)
        if is_base:
            out.append(
                f'<text x="{x_after + 10:.1f}" y="{mid}" font-size="9.5" '
                f'fill="#c0392b">← baseline</text>'
            )
            x_after += 10 + text_width("← baseline", 9.5)
        _require_fits("value", value_text, x_after, width)

    out.append(
        f'<text x="22" y="{height - 16}" font-size="11" fill="#111" '
        f'font-weight="600">bars: × to {BASELINE_LABEL}=1.00, then absolute {unit} '
        f"(higher is better)</text>"
    )
    out.append("</svg>")
    out_dir.mkdir(parents=True, exist_ok=True)
    svg = out_dir / f"stage-{stage}.svg"
    svg.write_text("\n".join(out), encoding="utf-8")
    _export_png(svg)
    return svg


def render_combined(
    results: dict[str, dict[str, float]],
    out_dir: Path,
    *,
    subtitle: str = "same session, best of rounds",
) -> Path:
    """Render all stages as grouped bars, one group per stage."""
    stages = [s for s in STAGE_ORDER if s in results]
    stages += [s for s in results if s not in stages]
    apps = [a for a in PALETTE if any(a[0] in results[s] for s in stages)]
    ratios = {
        s: {
            a[0]: results[s][a[0]] / (results[s].get(BASELINE) or max(results[s].values()))
            for a in apps
            if a[0] in results[s]
        }
        for s in stages
    }
    x_max = max(2.0, round(max(max(r.values()) for r in ratios.values()) * 1.2, 1))

    bar_h, bar_gap = 12, 2
    group_head, group_gap = 22, 26
    x0, plot_w = 312, 390
    head, foot = 152, 60
    group_h = group_head + len(apps) * (bar_h + bar_gap) - bar_gap
    height = head + len(stages) * (group_h + group_gap) - group_gap + foot
    ratio_font, value_font = 9.5, 9.5

    def sx(ratio: float) -> float:
        return x0 + ratio / x_max * plot_w

    labels_need = max(
        LABEL_GAP
        + text_width(f"×{ratios[s][a[0]]:.2f}", ratio_font)
        + RATIO_VALUE_GAP
        + text_width(_num(results[s][a[0]]), value_font)
        for s in stages
        for a in apps
        if a[0] in results[s]
    )
    width = max(
        x0 + plot_w + 60,
        sx(max(max(r.values()) for r in ratios.values())) + labels_need + EDGE_PAD,
    )

    out: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="{FONT}">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        '<text x="22" y="34" font-size="20" font-weight="700" fill="#111">'
        "cyjwt vs PyJWT: throughput</text>",
        f'<text x="22" y="56" font-size="12" fill="#555">{BASELINE_LABEL} = 1.00 on every '
        f"stage ({_esc(subtitle)})</text>",
    ]
    for i, (_, label, colour) in enumerate(apps):
        col, row = i % 3, i // 3
        lx, ly = 22 + col * 290, 78 + row * 16
        out.append(f'<rect x="{lx}" y="{ly - 8}" width="9" height="9" rx="2" fill="{colour}"/>')
        out.append(
            f'<text x="{lx + 13}" y="{ly}" font-size="10.5" fill="#333">{_esc(label)}</text>'
        )

    for tick in _ticks(x_max):
        x = sx(tick)
        is_base = abs(tick - 1.0) < 1e-9
        colour = "#c0392b" if is_base else "#ececec"
        dash = ' stroke-dasharray="5 3"' if is_base else ""
        out.append(
            f'<line x1="{x:.1f}" y1="{head - 12}" x2="{x:.1f}" '
            f'y2="{height - foot + 4}" stroke="{colour}" '
            f'stroke-width="{1.6 if is_base else 1}"{dash}/>'
        )
        out.append(
            f'<text x="{x:.1f}" y="{height - foot + 20}" font-size="10.5" '
            f'fill="#666" text-anchor="middle">×{tick:g}</text>'
        )

    for gi, stage in enumerate(stages):
        top = head + gi * (group_h + group_gap)
        out.append(
            f'<text x="22" y="{top + 1}" font-size="12.5" font-weight="700" '
            f'fill="#111">{_esc(stage_title(stage))}</text>'
        )
        for ai, (app, label, colour) in enumerate(apps):
            if app not in results[stage]:
                continue
            y = top + group_head + ai * (bar_h + bar_gap)
            mid = y + bar_h - 3
            ratio = ratios[stage][app]
            is_base = app == BASELINE
            out.append(f'<rect x="22" y="{y + 2}" width="7" height="7" rx="1.5" fill="{colour}"/>')
            weight = ' font-weight="700"' if is_base else ""
            out.append(
                f'<text x="34" y="{mid}" font-size="10" fill="#2b2b2b"{weight}>'
                f"{_esc(SHORT_LABELS.get(app, label))}</text>"
            )
            end = sx(ratio)
            out.append(
                f'<rect x="{x0}" y="{y}" width="{max(end - x0, 1.2):.1f}" '
                f'height="{bar_h}" rx="2" fill="{colour}"/>'
            )
            fill = "#c0392b" if is_base else "#333"
            ratio_text = f"×{ratio:.2f}"
            x_ratio = end + LABEL_GAP
            x_value = x_ratio + text_width(ratio_text, ratio_font) + RATIO_VALUE_GAP
            out.append(
                f'<text x="{x_ratio:.1f}" y="{mid}" font-size="{ratio_font}" '
                f'fill="{fill}"{weight}>{ratio_text}</text>'
            )
            value_text = _num(results[stage][app])
            out.append(
                f'<text x="{x_value:.1f}" y="{mid}" font-size="{value_font}" '
                f'fill="#666">{value_text}</text>'
            )
            _require_fits(
                "value",
                value_text,
                x_value + text_width(value_text, value_font),
                width,
            )

    out.append("</svg>")
    out_dir.mkdir(parents=True, exist_ok=True)
    svg = out_dir / "bench-cyjwt-vs-pyjwt.svg"
    svg.write_text("\n".join(out), encoding="utf-8")
    _export_png(svg)
    return svg


def load_results(results_dir: Path) -> tuple[dict[str, dict[str, float]], int]:
    results: dict[str, dict[str, float]] = {}
    runs = 0
    for path in sorted(results_dir.glob("stage-*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        results[payload["stage"]] = payload["values"]
        runs = max(runs, int(payload.get("runs", 1)))
    return results, runs


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    check_only = "--check" in args
    args = [a for a in args if a != "--check"]
    root = Path(args[0]) if args else ROOT
    results_dir = root / "benchmarks" / "results"
    charts_dir = (
        Path(tempfile.mkdtemp(prefix="cyjwt-charts-"))
        if check_only
        else root / "docs" / "img" / "charts"
    )

    results, runs = load_results(results_dir)
    if not results:
        raise SystemExit(f"no stage-*.json in {results_dir}; run benchmarks/bench.py first")

    for stage, values in results.items():
        svg = render_stage(
            stage,
            values,
            charts_dir,
            subtitle=f"best of {runs} rounds",
        )
        print(f"{stage:20s} → {svg}")

    svg = render_combined(results, charts_dir, subtitle=f"best of {runs} rounds")
    print(f"{'combined':20s} → {svg}")

    if check_only:
        print(f"layout ok: {len(results) + 1} charts, labels fit")


if __name__ == "__main__":
    main()
