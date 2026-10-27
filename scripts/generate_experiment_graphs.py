#!/usr/bin/env python3
"""Generate dependency-free SVG graphs from saved experiment JSON files.

The project intentionally does not depend on a plotting package.  This script
keeps graph generation reproducible on a clean Python installation and writes
the graphs beside the JSON measurements.
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def _svg(title: str, bars: list[tuple[str, float, str]], ylabel: str) -> str:
    width, height = 760, 420
    chart_left, chart_top = 80, 70
    chart_width, chart_height = 620, 270
    maximum = max((value for _, value, _ in bars), default=1.0) or 1.0
    bar_width = chart_width / max(1, len(bars)) * 0.68
    gap = chart_width / max(1, len(bars))
    elements = [
        f'<text x="{width / 2:.0f}" y="30" text-anchor="middle" '
        f'font-family="sans-serif" font-size="18">{title}</text>',
        f'<text x="18" y="{chart_top + chart_height / 2:.0f}" '
        f'transform="rotate(-90 18 {chart_top + chart_height / 2:.0f})" '
        f'font-family="sans-serif" font-size="12">{ylabel}</text>',
        f'<line x1="{chart_left}" y1="{chart_top + chart_height}" '
        f'x2="{chart_left + chart_width}" y2="{chart_top + chart_height}" '
        f'stroke="#333"/>',
        f'<line x1="{chart_left}" y1="{chart_top}" '
        f'x2="{chart_left}" y2="{chart_top + chart_height}" stroke="#333"/>',
    ]
    for index, (label, value, colour) in enumerate(bars):
        x = chart_left + gap * index + (gap - bar_width) / 2
        bar_height = chart_height * value / maximum
        y = chart_top + chart_height - bar_height
        elements.extend(
            [
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width:.1f}" '
                f'height="{bar_height:.1f}" fill="{colour}"/>',
                f'<text x="{x + bar_width / 2:.1f}" y="{y - 7:.1f}" '
                f'text-anchor="middle" font-family="sans-serif" font-size="11">'
                f'{value:.2f}</text>',
                f'<text x="{x + bar_width / 2:.1f}" '
                f'y="{chart_top + chart_height + 22}" text-anchor="middle" '
                f'font-family="sans-serif" font-size="11">{label}</text>',
            ]
        )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}">'
        + "".join(elements)
        + "</svg>\n"
    )


def main() -> None:
    cold_warm = _load("experiments/cold_warm/results.json")
    (ROOT / "experiments/cold_warm/latency.svg").write_text(
        _svg(
            "Cold versus warm resolution latency",
            [
                ("cold", cold_warm["cold"]["summary"]["mean_ms"], "#c95c5c"),
                ("warm", cold_warm["warm"]["summary"]["mean_ms"], "#4c9a6a"),
            ],
            "mean milliseconds",
        ),
        encoding="utf-8",
    )

    hit_ratio = _load("experiments/cache_hit_ratio/results.json")
    (ROOT / "experiments/cache_hit_ratio/hit_ratio.svg").write_text(
        _svg(
            "Cache hit ratio over replayed trace",
            [("hit ratio", hit_ratio["hit_ratio"] * 100, "#4c7fb3")],
            "percent",
        ),
        encoding="utf-8",
    )

    query_count_path = ROOT / "experiments/query_count/results_dig.json"
    query_count = json.loads(
        query_count_path.read_text(encoding="utf-8")
        if query_count_path.is_file()
        else (ROOT / "experiments/query_count/results.json").read_text(encoding="utf-8")
    )
    bars = [("resolver", float(query_count["resolver_query_count"]), "#4c7fb3")]
    if query_count.get("dig_trace_query_count") is not None:
        bars.append(("dig +trace", float(query_count["dig_trace_query_count"]), "#8c63a8"))
    (ROOT / "experiments/query_count/query_count.svg").write_text(
        _svg("Resolver query count comparison", bars, "responses"),
        encoding="utf-8",
    )

    unreachable = _load("experiments/unreachable_authoritative/results.json")
    (ROOT / "experiments/unreachable_authoritative/failover.svg").write_text(
        _svg(
            "Authoritative failover attempts",
            [
                (name.split(".", 1)[0], float(attempts), "#c95c5c" if name.startswith("authority-a") else "#4c9a6a")
                for name, attempts in unreachable["udp_attempts"].items()
            ],
            "UDP sends",
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
