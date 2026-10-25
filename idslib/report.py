"""Timeline plot + self-contained HTML report (the 'analyst view')."""
from __future__ import annotations

import base64
import html
import io
from typing import Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

SEV_COLOR = {"Critical": "#b3261e", "High": "#d9480f", "Medium": "#b7791f", "Low": "#6b7280"}


def timeline_png(res, path: Optional[str] = None, title: str = "") -> bytes:
    df, W = res.cap.df, res.cap.window
    flagged = {a["src"] for a in res.alerts}
    fig, ax = plt.subplots(figsize=(10, 3.8), dpi=130)
    for src, g in df.groupby("src"):
        hot = src in flagged
        ax.plot(g["t_start"] + W / 2, g["pps"], lw=2.0 if hot else 0.9, color="#b3261e" if hot else "#9aa4b2",
                alpha=1 if hot else 0.7, label=src if hot else None, zorder=3 if hot else 2)
    for a in res.alerts:
        ax.axvspan(a["t_start"], a["t_start"] + W, color=SEV_COLOR[a["severity"]], alpha=0.10, lw=0)
    ax.set_yscale("symlog", linthresh=10)
    ax.set_xlabel("time since capture start (s)")
    ax.set_ylabel("packets / s per source (log)")
    ax.set_title(title or "Per-source packet rate; shaded = alerted window", fontsize=10, loc="left")
    ax.spines[["top", "right"]].set_visible(False)
    if flagged:
        ax.legend(frameon=False, fontsize=8, title="alerted sources", title_fontsize=8)
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    if path:
        fig.savefig(path)
    plt.close(fig)
    return buf.getvalue()


def write_html(res, path: str, title: str = "capture") -> None:
    img = base64.b64encode(timeline_png(res, title=title)).decode()
    rows = []
    for a in res.alerts:
        ev = ", ".join(f"{k}={v}" for k, v in a["evidence"].items() if k != "deviations")
        rows.append(
            f"<tr><td>{a['id']}</td><td>{a['t_start']:.0f}s</td><td>{html.escape(a['src'])}</td>"
            f"<td><b>{a['category']}</b></td><td style='color:{SEV_COLOR[a['severity']]}'><b>{a['severity']}</b></td>"
            f"<td>{a['confidence']:.2f}</td><td>{a['detector']}</td><td>{html.escape(str(a.get('dst') or '-'))}</td>"
            f"<td>{html.escape(a['why'])}<br><small>{html.escape(ev)}</small></td></tr>")
    cap = res.cap
    doc = f"""<!doctype html><meta charset=utf-8><title>IDS report - {html.escape(title)}</title>
<style>body{{font:14px system-ui;margin:2rem;max-width:1200px;color:#1f2430}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #e3e6eb;padding:6px 8px;text-align:left;vertical-align:top}}th{{background:#f3f5f8}}
small{{color:#667}}img{{max-width:100%}}</style>
<h2>IDS report - {html.escape(title)}</h2>
<p>{cap.n_packets} packets, {cap.t1 - cap.t0:.1f}s, {len(cap.df)} source-windows ({cap.window:g}s), mode <b>{res.mode}</b>,
<b>{len(res.alerts)}</b> alert(s)</p>
<img src="data:image/png;base64,{img}" alt="timeline">
<table><tr><th>#</th><th>t</th><th>source</th><th>category</th><th>severity</th><th>conf</th><th>by</th><th>target</th><th>why</th></tr>
{''.join(rows) or '<tr><td colspan=9>No alerts</td></tr>'}</table>"""
    with open(path, "w") as f:
        f.write(doc)
