"""Menyusun dan menampilkan laporan hasil audit."""

import json
from collections import defaultdict, Counter

from .models import Status

COLOR = {
    Status.PASS: "\033[92m",   # hijau
    Status.FAIL: "\033[91m",   # merah
    Status.WARN: "\033[93m",   # kuning
    Status.MANUAL: "\033[94m",  # biru
    Status.SKIP: "\033[90m",   # abu
    Status.ERROR: "\033[95m",  # magenta
}
RESET = "\033[0m"


def print_console_report(results: list):
    by_category = defaultdict(list)
    for r in results:
        by_category[r.category].append(r)

    counter = Counter(r.status for r in results)

    print("\n" + "=" * 78)
    print(" KAFKA SECURITY AUDIT REPORT")
    print("=" * 78)

    for category, items in by_category.items():
        print(f"\n## {category}")
        for r in sorted(items, key=lambda x: x.id):
            color = COLOR.get(r.status, "")
            print(f"  [{color}{r.status.value:7s}{RESET}] {r.id:6s} {r.title}")
            if r.detail:
                print(f"           detail : {r.detail}")
            if r.recommendation:
                print(f"           saran  : {r.recommendation}")

    print("\n" + "-" * 78)
    print(" RINGKASAN")
    print("-" * 78)
    for status in Status:
        if counter[status]:
            color = COLOR.get(status, "")
            print(f"  {color}{status.value:7s}{RESET}: {counter[status]}")
    total_checked = counter[Status.PASS] + counter[Status.FAIL] + counter[Status.WARN]
    if total_checked:
        score = counter[Status.PASS] / total_checked * 100
        print(f"\n  Skor kepatuhan (dari item yang otomatis bisa dicek PASS/FAIL/WARN): {score:.1f}%")
    print(f"  Item MANUAL/SKIP yang butuh review tambahan: {counter[Status.MANUAL] + counter[Status.SKIP]}")
    print("=" * 78 + "\n")


def export_json(results: list, path: str):
    with open(path, "w") as f:
        json.dump([r.to_dict() for r in results], f, indent=2, ensure_ascii=False)


def export_html(results: list, path: str):
    by_category = defaultdict(list)
    for r in results:
        by_category[r.category].append(r)

    status_colors = {
        "PASS": "#16a34a", "FAIL": "#dc2626", "WARN": "#d97706",
        "MANUAL": "#2563eb", "SKIP": "#6b7280", "ERROR": "#9333ea",
    }

    rows_html = ""
    for category, items in by_category.items():
        rows_html += f'<tr class="cat-row"><td colspan="4"><strong>{category}</strong></td></tr>'
        for r in sorted(items, key=lambda x: x.id):
            color = status_colors.get(r.status.value, "#000")
            rows_html += f"""
            <tr>
              <td>{r.id}</td>
              <td>{r.title}</td>
              <td><span style="color:white;background:{color};padding:2px 8px;border-radius:4px;font-size:12px">{r.status.value}</span></td>
              <td><div>{r.detail}</div><div style="color:#555;font-size:13px">{r.recommendation}</div></td>
            </tr>"""

    counter = Counter(r.status.value for r in results)
    summary_html = "".join(
        f'<span style="margin-right:16px"><strong>{k}</strong>: {v}</span>' for k, v in counter.items()
    )

    html = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<title>Kafka Security Audit Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; color: #1a1a1a; }}
  h1 {{ font-size: 22px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e5e5; vertical-align: top; }}
  th {{ background: #f5f5f5; }}
  .cat-row td {{ background: #fafafa; padding-top: 16px; font-size: 15px; }}
  .summary {{ margin-top: 12px; padding: 12px; background: #f5f5f5; border-radius: 8px; }}
</style>
</head>
<body>
  <h1>Kafka Security Audit Report</h1>
  <div class="summary">{summary_html}</div>
  <table>
    <thead><tr><th>ID</th><th>Item</th><th>Status</th><th>Detail &amp; Saran</th></tr></thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
