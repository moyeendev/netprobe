"""One-click correlation report (self-contained HTML + JSON).

The HTML has no external dependencies: data are embedded as JSON and drawn
as stacked small-multiple SVG panels sharing one time axis (the session
clock), with the load window shaded, congestion onset marked, a shared
hover crosshair, and a phase table that doubles as the accessible table
view of the figure.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from netprobe.analysis.correlate import Correlation, correlate

PANELS = [
    # key, title, unit label, scale
    ("stress.offered_rate", "Offered load", "Mbit/s", 1e-6),
    ("bandwidth.throughput", "TCP throughput", "Mbit/s", 1e-6),
    ("delay.rtt", "RTT (median per bin)", "ms", 1.0),
    ("delay.lost", "Lost probes", "per bin", 1.0),
    ("bandwidth.tcp_rtt", "Kernel TCP sRTT", "ms", 1.0),
    ("sniff.tcp_retrans", "Retransmissions on the wire", "per bin", 1.0),
    ("congestion.level", "Congestion level", "0-3", 1.0),
]


def _fmt(v, unit=""):
    if v is None:
        return "–"
    if unit == "bps":
        return f"{v / 1e6:.2f} Mbit/s"
    if unit == "ms":
        return f"{v:.2f} ms"
    if unit == "ratio":
        return f"{100 * v:.2f} %"
    if isinstance(v, float):
        return f"{v:.3g}"
    return str(v)


def _phase_table(corr: Correlation) -> str:
    cols = [
        ("rtt_median_ms", "RTT median", "ms"), ("rtt_p95_ms", "RTT p95", "ms"),
        ("jitter_ms", "Jitter", "ms"), ("loss", "Loss", "ratio"),
        ("throughput_mean_bps", "Throughput", "bps"), ("tcp_retrans", "TCP retrans", ""),
        ("wire_retrans", "Wire retrans", ""), ("offered_load_mean_bps", "Offered load", "bps"),
    ]
    head = "".join(f"<th>{html.escape(c[1])}</th>" for c in cols)
    rows = []
    for name, st in corr.phases.items():
        cells = "".join(f"<td>{_fmt(st.get(k), u)}</td>" for k, _, u in cols)
        rows.append(f"<tr><th scope='row'>{html.escape(name)}<br><span class='muted'>"
                    f"{st['t0_s']:.1f}–{st['t1_s']:.1f} s</span></th>{cells}</tr>")
    return f"<table><thead><tr><th>Phase</th>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def build_report_data(corr: Correlation, manifest: dict) -> dict:
    tl = corr.timeline
    panels = []
    for key, title, unit, scale in PANELS:
        if key in tl.series:
            vals = [None if v is None else v * scale for v in tl.series[key]]
            if key == "stress.offered_rate":
                vals = [0.0 if v is None else v for v in vals]
            panels.append({"key": key, "title": title, "unit": unit, "values": vals})
    return {
        "run_id": corr.run_id,
        "bin_s": tl.bin_s,
        "t": tl.t,
        "panels": panels,
        "stress": [{"start": s.start_s, "stop": s.stop_s} for s in corr.stress],
        "onset": corr.onset_s,
        "recovery": corr.recovery_s,
        "label": manifest.get("label"),
    }


_CSS = """
:root{color-scheme:light;--surface:#fcfcfb;--panel:#ffffff;--ink:#0b0b0b;--ink2:#52514e;
--muted:#8a8984;--grid:#e8e7e3;--series:#2a78d6;--band:rgba(82,81,78,.10);--onset:#e34948;
--border:#e2e1dc}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;
--surface:#1a1a19;--panel:#222221;--ink:#f0efec;--ink2:#c3c2b7;--muted:#8f8e86;--grid:#33332f;
--series:#3987e5;--band:rgba(240,239,236,.10);--onset:#e66767;--border:#3a3a36}}
:root[data-theme="dark"]{color-scheme:dark;--surface:#1a1a19;--panel:#222221;--ink:#f0efec;
--ink2:#c3c2b7;--muted:#8f8e86;--grid:#33332f;--series:#3987e5;--band:rgba(240,239,236,.10);
--onset:#e66767;--border:#3a3a36}
body{margin:0;background:var(--surface);color:var(--ink);
font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1040px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px}
.muted{color:var(--muted);font-size:12px}.sub{color:var(--ink2);margin:0 0 16px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.tile{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:12px}
.tile b{display:block;font-size:22px;font-variant-numeric:tabular-nums}
.tile span{color:var(--ink2);font-size:12px}
.chart{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:8px 8px 4px;
position:relative}
svg text{fill:var(--ink2);font-size:11px}.ptitle{fill:var(--ink);font-size:12px;font-weight:600}
#tip{position:absolute;pointer-events:none;background:var(--panel);border:1px solid var(--border);
border-radius:6px;padding:6px 8px;font-size:12px;display:none;box-shadow:0 2px 8px rgba(0,0,0,.15);
font-variant-numeric:tabular-nums;white-space:nowrap}
.tablewrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{border-bottom:1px solid var(--border);padding:6px 8px;text-align:right;font-size:13px}
th:first-child,td:first-child{text-align:left}thead th{color:var(--ink2);font-weight:600}
code{font-size:12px}
"""

_JS = r"""
const D = JSON.parse(document.getElementById('data').textContent);
const host = document.getElementById('panels'), tip = document.getElementById('tip');
const W = 1000, H = 110, L = 64, R = 16, T = 22, B = 18, NS = 'http://www.w3.org/2000/svg';
const tMax = D.t.length ? D.t[D.t.length-1] + D.bin_s : 1;
const x = t => L + (W-L-R) * t / tMax;
function el(n, a, p){const e=document.createElementNS(NS,n);for(const k in a)e.setAttribute(k,a[k]);
 if(p)p.appendChild(e);return e;}
const svg = el('svg', {viewBox:`0 0 ${W} ${(H)*D.panels.length+24}`, width:'100%', role:'img',
  'aria-label':'Stacked timeline panels sharing the session clock'}, host);
const cross = [];
D.panels.forEach((p, i) => {
  const y0 = i*H, vals = p.values.filter(v => v !== null);
  let vmax = vals.length ? Math.max(...vals) : 1; if (vmax <= 0) vmax = 1; vmax *= 1.1;
  const y = v => y0 + T + (H-T-B) * (1 - v / vmax);
  D.stress.forEach(s => el('rect', {x:x(s.start), y:y0+T, width:x(s.stop ?? tMax)-x(s.start),
    height:H-T-B, fill:'var(--band)'}, svg));
  [0, .5, 1].forEach(f => { const yy = y(vmax/1.1*f);
    el('line', {x1:L, x2:W-R, y1:yy, y2:yy, stroke:'var(--grid)', 'stroke-width':1}, svg);
    const tx = el('text', {x:L-6, y:yy+4, 'text-anchor':'end'}, svg);
    tx.textContent = (vmax/1.1*f).toPrecision(3).replace(/\.?0+$/,''); });
  const ti = el('text', {x:L, y:y0+14, class:'ptitle'}, svg); ti.textContent = p.title;
  const tu = el('text', {x:L + 8 + p.title.length*6.6, y:y0+14}, svg); tu.textContent = p.unit;
  let d = '', pen = false;
  p.values.forEach((v, j) => { if (v === null) { pen = false; return; }
    const px = x(D.t[j] + D.bin_s/2), py = y(v); d += (pen ? 'L' : 'M') + px.toFixed(1) + ' ' + py.toFixed(1); pen = true; });
  el('path', {d, fill:'none', stroke:'var(--series)', 'stroke-width':2, 'stroke-linejoin':'round',
    'stroke-linecap':'round'}, svg);
  if (D.onset !== null) el('line', {x1:x(D.onset), x2:x(D.onset), y1:y0+T, y2:y0+H-B,
    stroke:'var(--onset)', 'stroke-width':1.5, 'stroke-dasharray':'4 3'}, svg);
  cross.push(el('line', {x1:0, x2:0, y1:y0+T, y2:y0+H-B, stroke:'var(--muted)', 'stroke-width':1,
    visibility:'hidden'}, svg));
});
const axY = H*D.panels.length + 4;
for (let k = 0; k <= 10; k++) { const t = tMax*k/10, tx = el('text', {x:x(t), y:axY+12, 'text-anchor':'middle'}, svg);
  tx.textContent = t.toFixed(0) + (k === 10 ? ' s' : ''); }
if (D.onset !== null) { const o = el('text', {x:x(D.onset)+4, y:12, fill:'var(--onset)'}, svg);
  o.style.fill = 'var(--onset)'; o.textContent = 'onset ' + D.onset.toFixed(1) + ' s'; }
const hit = el('rect', {x:L, y:0, width:W-L-R, height:axY, fill:'transparent'}, svg);
hit.addEventListener('mousemove', ev => {
  const pt = svg.createSVGPoint(); pt.x = ev.clientX; pt.y = ev.clientY;
  const sp = pt.matrixTransform(svg.getScreenCTM().inverse());
  const t = (sp.x - L) / (W-L-R) * tMax, j = Math.max(0, Math.min(D.t.length-1, Math.floor(t / D.bin_s)));
  const cx = x(D.t[j] + D.bin_s/2);
  cross.forEach(c => { c.setAttribute('x1', cx); c.setAttribute('x2', cx); c.setAttribute('visibility','visible'); });
  tip.innerHTML = `<b>t = ${D.t[j].toFixed(2)}–${(D.t[j]+D.bin_s).toFixed(2)} s</b><br>` +
    D.panels.map(p => `${p.title}: ${p.values[j] === null ? '–' : (+p.values[j]).toPrecision(4)} ${p.unit}`).join('<br>');
  const box = host.getBoundingClientRect(); tip.style.display = 'block';
  let lx = ev.clientX - box.left + 14; if (lx + 260 > box.width) lx -= 290;
  tip.style.left = lx + 'px'; tip.style.top = (ev.clientY - box.top + 10) + 'px';
});
hit.addEventListener('mouseleave', () => { tip.style.display = 'none';
  cross.forEach(c => c.setAttribute('visibility','hidden')); });
"""


def render_html(corr: Correlation, manifest: dict) -> str:
    data = build_report_data(corr, manifest)
    lat = corr.detection_latency_s
    ev = corr.evidence
    ev_text = "–"
    if ev and ev.get("frame_first"):
        ev_text = (f"frames {ev['frame_first']}–{ev['frame_last']} in "
                   f"<code>{html.escape(str(ev['pcap']))}</code>, {ev['tcp_retrans']} retrans")
    lag_rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td>{v['lag_s']:+.2f} s</td><td>{v['r']:.2f}</td>"
        f"<td>{_fmt(v['r_at_zero'])}</td></tr>" for k, v in corr.lags.items())
    base = corr.congestion.baseline
    notes = "".join(f"<li>{html.escape(n)}</li>" for n in corr.notes)
    title = f"NetProbe report — {html.escape(str(corr.run_id))}"
    data_json = json.dumps(data).replace("</", "<\\/")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
<style>{_CSS}</style></head><body><main>
<h1>{title}</h1>
<p class="sub">Target {html.escape(str(manifest.get('target')))} · NetProbe
{html.escape(str(manifest.get('version')))} · {html.escape(str(manifest.get('host', {}).get('system')))}
{html.escape(str(manifest.get('host', {}).get('release')))} · all series on one session clock</p>
<div class="tiles">
<div class="tile"><span>Congestion onset</span><b>{_fmt(corr.onset_s)}{' s' if corr.onset_s is not None else ''}</b></div>
<div class="tile"><span>Decision latency after load start</span><b>{(f'{lat:+.2f} s' if lat is not None else '–')}</b></div>
<div class="tile"><span>Recovery</span><b>{_fmt(corr.recovery_s)}{' s' if corr.recovery_s is not None else ''}</b></div>
<div class="tile"><span>Capture evidence at onset</span><b style="font-size:13px">{ev_text}</b></div>
</div>
<h2>Timeline</h2>
<p class="muted">Shaded: load window. Dashed: detected congestion onset. Hover for values per {corr.timeline.bin_s:g} s bin.</p>
<div class="chart" id="panels"><div id="tip"></div></div>
<h2>Phases</h2><div class="tablewrap">{_phase_table(corr)}</div>
<h2>Load → effect lag</h2>
<p class="muted">Lagged Pearson correlation between offered load and each series; positive lag = effect follows load.</p>
<div class="tablewrap"><table><thead><tr><th>Pair</th><th>Best lag</th><th>r at best lag</th><th>r at 0</th></tr></thead>
<tbody>{lag_rows or '<tr><td colspan=4>no load applied</td></tr>'}</tbody></table></div>
<h2>Detector</h2>
<p class="muted">Baseline (windows ending ≤ {base['end_s']:.1f} s): RTT {_fmt(base['rtt_ms'], 'ms')},
loss {_fmt(base['loss'], 'ratio')}, throughput {_fmt(base['throughput_bps'], 'bps')}.
Config: <code>{html.escape(json.dumps(corr.to_dict()['congestion']['config']))}</code></p>
{f'<ul>{notes}</ul>' if notes else ''}
<script type="application/json" id="data">{data_json}</script>
<script>{_JS}</script>
</main></body></html>"""


def write_report(records, manifest: dict, html_path: Path, **correlate_kw) -> Path:
    corr = correlate(records, manifest=manifest, **correlate_kw)
    html_path = Path(html_path)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(render_html(corr, manifest), encoding="utf-8")
    html_path.with_suffix(".json").write_text(json.dumps(corr.to_dict(), indent=1),
                                              encoding="utf-8")
    html_path.with_name("timeline.csv").write_text(corr.timeline.to_csv(), encoding="utf-8")
    return html_path
