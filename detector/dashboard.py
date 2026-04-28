"""
dashboard.py — live metrics web UI on port 8888
"""
from flask import Flask, jsonify, render_template_string
import psutil
import time

app = Flask(__name__)
_state = {}

HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>HNG Detector Dashboard</title>
  <meta http-equiv="refresh" content="3">
  <style>
    body{font-family:monospace;background:#0d1117;
         color:#c9d1d9;padding:20px}
    h1{color:#58a6ff}
    h2{color:#f0883e;border-bottom:1px solid #30363d;padding-bottom:5px}
    table{width:100%;border-collapse:collapse;margin:10px 0}
    th,td{padding:8px 12px;text-align:left;border:1px solid #30363d}
    th{background:#161b22;color:#58a6ff}
    tr:nth-child(even){background:#161b22}
    .red{background:#da3633;color:white;padding:2px 8px;border-radius:4px}
    .green{color:#3fb950}
    .box{display:inline-block;background:#161b22;border:1px solid #30363d;
         border-radius:6px;padding:15px 25px;margin:8px;min-width:140px}
    .val{font-size:2em;color:#58a6ff}
    .lbl{font-size:0.8em;color:#8b949e}
  </style>
</head>
<body>
  <h1>&#128737; HNG Anomaly Detector</h1>
  <p>Refreshes every 3s &nbsp;|&nbsp;
     <span class="green">Uptime: {{ uptime }}</span></p>

  <h2>System Metrics</h2>
  <div>
    <div class="box"><div class="val">{{ g_rate }}</div>
      <div class="lbl">Global req/60s</div></div>
    <div class="box"><div class="val">{{ cpu }}%</div>
      <div class="lbl">CPU</div></div>
    <div class="box"><div class="val">{{ mem }}%</div>
      <div class="lbl">Memory</div></div>
    <div class="box"><div class="val">{{ mean }}</div>
      <div class="lbl">Baseline Mean</div></div>
    <div class="box"><div class="val">{{ stddev }}</div>
      <div class="lbl">Stddev</div></div>
    <div class="box"><div class="val">{{ n_banned }}</div>
      <div class="lbl">Banned IPs</div></div>
  </div>

  <h2>Banned IPs</h2>
  {% if banned %}
  <table>
    <tr><th>IP</th><th>Ban #</th><th>Banned At</th>
        <th>Unban At</th><th>Rate</th></tr>
    {% for ip,i in banned.items() %}
    <tr>
      <td><span class="red">{{ ip }}</span></td>
      <td>{{ i.count }}</td>
      <td>{{ i.banned_str }}</td>
      <td>{{ i.unban_str }}</td>
      <td>{{ i.rate }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="green">&#10003; No IPs currently banned</p>
  {% endif %}

  <h2>Top 10 IPs (last 60s)</h2>
  <table>
    <tr><th>#</th><th>IP</th><th>Requests</th></tr>
    {% for i,(ip,c) in enumerate(top_ips, 1) %}
    <tr><td>{{ i }}</td><td>{{ ip }}</td><td>{{ c }}</td></tr>
    {% endfor %}
  </table>
</body>
</html>
"""


def _fmt(ts):
    return "PERMANENT" if ts is None \
        else time.strftime("%H:%M:%S", time.gmtime(ts))


def _uptime():
    s = int(time.time() - _state.get("start", time.time()))
    h, r = divmod(s, 3600)
    m, s = divmod(r, 60)
    return f"{h}h {m}m {s}s"


@app.route("/")
def index():
    det = _state.get("detector")
    bl = _state.get("baseline")
    bk = _state.get("blocker")

    raw = bk.get_banned() if bk else {}
    banned = {ip: {**i,
                   "banned_str": _fmt(i.get("banned_at")),
                   "unban_str":  _fmt(i.get("unban_at"))}
              for ip, i in raw.items()}

    stats = bl.get_stats() if bl else {}
    return render_template_string(
        HTML,
        banned=banned,
        n_banned=len(banned),
        top_ips=det.get_top_ips(10) if det else [],
        g_rate=det.get_global_rate() if det else 0,
        cpu=round(psutil.cpu_percent(), 1),
        mem=round(psutil.virtual_memory().percent, 1),
        mean=stats.get("mean", 0),
        stddev=stats.get("stddev", 0),
        uptime=_uptime(),
        enumerate=enumerate,
    )


@app.route("/api/metrics")
def api():
    det = _state.get("detector")
    bl = _state.get("baseline")
    bk = _state.get("blocker")
    stats = bl.get_stats() if bl else {}
    return jsonify({
        "global_rate": det.get_global_rate() if det else 0,
        "banned_ips":  list(bk.get_banned().keys()) if bk else [],
        "top_ips":     det.get_top_ips(10) if det else [],
        "cpu":         psutil.cpu_percent(),
        "memory":      psutil.virtual_memory().percent,
        "baseline":    stats,
        "uptime":      _uptime(),
    })


def start(detector, baseline, blocker, port):
    _state["detector"] = detector
    _state["baseline"] = baseline
    _state["blocker"] = blocker
    _state["start"] = time.time()
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
