"""
CyberNet - Network Connectivity & Security Analyzer
Discrete Mathematics course project (Graph Theory, Sets, Relations, Logic, BFS)

Run locally :  python app.py
Render      :  start command  ->  gunicorn app:app
"""
from collections import deque
from flask import Flask, render_template_string, request

app = Flask(__name__)

DEFAULT_DEVICES = "PC1\nPC2\nPC3\nRouter\nServer"
DEFAULT_CONNECTIONS = "PC1,Router,yes\nPC2,PC1,yes\nPC3,Router,yes\nRouter,Server,yes"


# --------------------------------------------------------------------------
# 1. Parsing  (names are compared case-insensitively and trimmed, so
#    "pc1", " PC1 " and "PC1" are the same vertex - a common cause of
#    "No path found" / "Disconnected" bugs)
# --------------------------------------------------------------------------
def key(name):
    return " ".join(name.strip().split()).lower()


def parse_devices(text):
    """One device per line (commas also accepted). Returns (display list, key->display map)."""
    names, seen = [], {}
    for raw in text.replace(",", "\n").splitlines():
        label = " ".join(raw.strip().split())
        if label and key(label) not in seen:
            seen[key(label)] = label
            names.append(label)
    return names, seen


def parse_connections(text, seen):
    """
    Accepts   A,B,yes/no   or   A-B   or   A - B,yes/no
    one per line or several separated by ';' . Returns (edges, errors).
    Edge = (a, b, authorized_bool). Unknown devices are added automatically.
    """
    edges, errors = [], []
    for raw in text.replace(";", "\n").splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        auth = True
        if len(parts) >= 3 and parts[-1].lower() in ("yes", "no", "y", "n"):
            auth = parts[-1].lower() in ("yes", "y")
            parts = parts[:-1]
        if len(parts) == 1:                       # "A-B" style
            for dash in ("-", "–", "—", ">"):
                if dash in parts[0]:
                    parts = [p.strip() for p in parts[0].split(dash, 1)]
                    break
        if len(parts) != 2 or not parts[0] or not parts[1]:
            errors.append(f"Could not read connection: '{line}'")
            continue
        a, b = parts
        if key(a) == key(b):
            errors.append(f"Ignored self-connection: '{line}'")
            continue
        for n in (a, b):
            if key(n) not in seen:
                seen[key(n)] = " ".join(n.split())
        edges.append((seen[key(a)], seen[key(b)], auth))
    return edges, errors


# --------------------------------------------------------------------------
# 2. Graph algorithms
# --------------------------------------------------------------------------
def build_graph(devices, edges):
    """Adjacency list for an undirected graph G = (V, E)."""
    g = {d: set() for d in devices}
    for a, b, _ in edges:
        g[a].add(b)
        g[b].add(a)
    return g


def components(g):
    """Connected components using BFS. Returns list of sets."""
    seen, comps = set(), []
    for s in g:
        if s in seen:
            continue
        comp, q = {s}, deque([s])
        seen.add(s)
        while q:
            u = q.popleft()
            for v in g[u]:
                if v not in seen:
                    seen.add(v)
                    comp.add(v)
                    q.append(v)
        comps.append(comp)
    return comps


def shortest_path(g, start, goal):
    """BFS shortest path (fewest edges). Returns list or None."""
    if start not in g or goal not in g:
        return None
    prev, q = {start: None}, deque([start])
    while q:
        u = q.popleft()
        if u == goal:
            path = []
            while u is not None:
                path.append(u)
                u = prev[u]
            return path[::-1]
        for v in sorted(g[u]):
            if v not in prev:
                prev[v] = u
                q.append(v)
    return None


def critical_devices(g):
    """Articulation points: removing the device increases the number of components."""
    base = len(components(g))
    crit = []
    for d in g:
        if not g[d]:
            continue
        reduced = {u: (nbrs - {d}) for u, nbrs in g.items() if u != d}
        if len(components(reduced)) > base:
            crit.append(d)
    return crit


# --------------------------------------------------------------------------
# 3. Logic / Boolean security rules
# --------------------------------------------------------------------------
def security_rules(devices, g, edges):
    """
    Rule 1:  unauthorized(connection)                     -> ALERT
    Rule 2:  device has an unauthorized connection        -> device = HIGH RISK
    Rule 3:  device is isolated (degree = 0)              -> device = WARNING
    Rule 4:  none of the above                            -> device = SAFE
    """
    alerts = [f"Unauthorized connection: {a} - {b}" for a, b, ok in edges if not ok]
    risky = {d for a, b, ok in edges if not ok for d in (a, b)}
    status = {}
    for d in devices:
        if d in risky:
            status[d] = "HIGH RISK"
        elif not g[d]:
            status[d] = "WARNING"
        else:
            status[d] = "SAFE"
    return alerts, status


def analyze(devices_text, connections_text, start, dest):
    devices, seen = parse_devices(devices_text)
    edges, errors = parse_connections(connections_text, seen)
    devices = devices + [n for k, n in seen.items() if n not in devices]
    g = build_graph(devices, edges)

    comps = components(g)
    connected = len(comps) == 1 and len(devices) > 0
    degree = {d: len(g[d]) for d in devices}
    top = max(degree.values()) if degree else 0
    most_connected = [d for d in devices if degree[d] == top and top > 0]
    crit = critical_devices(g)

    start_n = seen.get(key(start)) if start.strip() else None
    dest_n = seen.get(key(dest)) if dest.strip() else None
    path = shortest_path(g, start_n, dest_n) if start_n and dest_n else None
    path_msg = ""
    if not (start_n and dest_n):
        path_msg = "Start or destination device not found in the device list."

    alerts, status = security_rules(devices, g, edges)
    if any(s == "HIGH RISK" for s in status.values()):
        overall = "RISK"
    elif any(s == "WARNING" for s in status.values()) or not connected:
        overall = "WARNING"
    else:
        overall = "SAFE"

    return dict(
        devices=devices, edges=edges, errors=errors, graph=g, degree=degree,
        total=len(devices), links=len(edges), connected=connected,
        comps=[sorted(c) for c in comps], most=most_connected, crit=crit,
        path=path, path_msg=path_msg, start=start_n or start, dest=dest_n or dest,
        alerts=alerts, status=status, overall=overall,
    )


# --------------------------------------------------------------------------
# 4. Web page
# --------------------------------------------------------------------------
PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberNet - Network Connectivity &amp; Security Analyzer</title>
<style>
:root{--bg:#02040a;--card:#060a11;--line:#0b2a3d;--cy:#00d4ff;--tx:#e8f1f8;--mut:#7f93a6;--ok:#00d4ff;--warn:#ffb400;--bad:#ff4d5e}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 90%,#052233 0,#02040a 45%);color:var(--tx);font-family:"Segoe UI",Arial,sans-serif}
header{display:flex;justify-content:space-between;align-items:center;padding:20px 48px;border-bottom:1px solid #0a1a26;background:#000}
.logo{font-weight:900;letter-spacing:3px;font-size:22px}.logo b{color:var(--cy)}
header span{color:var(--mut);letter-spacing:1px}.on{color:var(--cy);font-size:13px;letter-spacing:2px}
main{max-width:1200px;margin:0 auto;padding:32px 24px 60px}
section{margin-bottom:34px}.num{color:var(--cy);letter-spacing:4px;font-size:13px}
h2{font-size:34px;letter-spacing:3px;margin:6px 0 4px;text-transform:uppercase}
.sub{color:var(--mut);margin:0 0 22px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:20px;padding:28px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:28px}
label{display:block;color:var(--cy);letter-spacing:3px;font-size:13px;font-weight:700;margin-bottom:6px}
.hint{color:#55677a;font-size:13px;margin-bottom:10px}
textarea,input{width:100%;background:#03060b;border:1px solid var(--line);border-radius:16px;color:var(--tx);padding:18px 20px;font:16px Consolas,monospace}
textarea{height:190px;resize:vertical}input{height:62px}
.row{display:grid;grid-template-columns:1fr 60px 1fr;gap:10px;align-items:end;margin-top:26px}
.arrow{text-align:center;color:var(--cy);font-size:26px;padding-bottom:16px}
button{width:100%;margin-top:30px;height:68px;border-radius:16px;border:1px solid #0a6aa8;background:linear-gradient(90deg,#04162b,#05202a);color:#fff;font-weight:800;letter-spacing:4px;font-size:17px;cursor:pointer}
button:hover{border-color:var(--cy)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:22px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:24px;min-height:150px;position:relative}
.stat small{color:var(--mut);letter-spacing:3px;font-size:12px}.stat .v{font-size:34px;font-weight:900;margin-top:20px}
.stat em{position:absolute;right:20px;bottom:14px;color:#0e3a52;font-style:normal;letter-spacing:3px;font-size:12px}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.box{background:var(--card);border:1px solid var(--line);border-radius:20px;padding:26px}
.tag{display:inline-block;width:38px;height:38px;line-height:36px;text-align:center;border:1px solid var(--cy);border-radius:9px;color:var(--cy);font-weight:800;margin-right:12px}
h3{display:flex;align-items:center;letter-spacing:3px;font-size:17px;margin:0 0 8px;text-transform:uppercase}
.item{display:flex;justify-content:space-between;align-items:center;background:#03060b;border:1px solid #0a1d2a;border-radius:12px;padding:20px;margin-top:12px}
.badge{width:40px;height:40px;border-radius:50%;border:1px solid #0a6aa8;background:#06283a;color:var(--cy);display:flex;align-items:center;justify-content:center}
.msg{background:#03060b;border:1px solid #0a1d2a;border-radius:12px;padding:22px;margin-top:14px;color:var(--mut)}
.path{font-size:20px;color:var(--cy);font-weight:700}
.vgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:18px;margin-top:16px}
.v{background:#03060b;border:1px solid #0a1d2a;border-radius:18px;padding:26px 12px;text-align:center}
.circle{width:74px;height:74px;margin:0 auto 16px;border:1px solid var(--cy);border-radius:50%;display:flex;align-items:center;justify-content:center;color:var(--cy);font-weight:800;font-size:20px}
.v b{font-size:20px}.v div{color:var(--mut);font-size:13px;margin-top:8px}
.chips span{display:inline-block;border:1px solid var(--line);background:#050b12;color:#8fb3cc;border-radius:8px;padding:12px 18px;margin:6px 10px 0 0;font-size:14px;letter-spacing:1px;text-transform:uppercase}
.err{color:var(--warn);margin:8px 0}
@media(max-width:800px){.grid2,.stats,.row{grid-template-columns:1fr}.arrow{display:none}header{padding:16px 20px}}
</style></head><body>
<header><div class="logo">&#9672; CYBER<b>NET</b></div><span>Network Connectivity &amp; Security Analyzer</span><div class="on">&#9679; SYSTEM ONLINE</div></header>
<main>
<form method="post" action="/">
<section><div class="num">01</div><h2>Network Input</h2><p class="sub">Enter devices and their connections.</p>
<div class="panel">
 <div class="grid2">
  <div><label>DEVICES</label><div class="hint">One device per line</div><textarea name="devices">{{ f.devices }}</textarea></div>
  <div><label>CONNECTIONS</label><div class="hint">Format: Device1,Device2,yes/no (yes = authorized)</div><textarea name="connections">{{ f.connections }}</textarea></div>
 </div>
 <div class="row">
  <div><label>START DEVICE</label><input name="start" value="{{ f.start }}"></div>
  <div class="arrow">&rarr;</div>
  <div><label>DESTINATION DEVICE</label><input name="dest" value="{{ f.dest }}"></div>
 </div>
 <button type="submit">ANALYZE NETWORK &nbsp;&rarr;</button>
</div></section>
</form>

{% if r %}
<section><div class="num">02</div><h2>Network Analysis</h2>
{% for e in r.errors %}<div class="err">&#9888; {{ e }}</div>{% endfor %}
<div class="stats">
 <div class="stat"><small>TOTAL DEVICES</small><div class="v">{{ r.total }}</div><em>NODE</em></div>
 <div class="stat"><small>CONNECTIONS</small><div class="v">{{ r.links }}</div><em>EDGE</em></div>
 <div class="stat"><small>CONNECTIVITY</small>
   <div class="v {{ 'ok' if r.connected else 'warn' }}">{{ 'CONNECTED' if r.connected else 'DISCONNECTED' }}</div><em>GRAPH</em></div>
 <div class="stat"><small>SECURITY</small>
   <div class="v {{ {'SAFE':'ok','WARNING':'warn','RISK':'bad'}[r.overall] }}">{{ r.overall }}</div><em>LOGIC</em></div>
</div></section>

<section class="grid2">
 <div class="box"><h3><span class="tag">A</span>Device Degree</h3><p class="sub">Number of connections for each device.</p>
  {% for d in r.devices %}<div class="item"><span>{{ d }}</span><span class="badge">{{ r.degree[d] }}</span></div>{% endfor %}</div>
 <div class="box"><h3><span class="tag">B</span>Critical Device</h3>
  <p class="sub">Most connected device, and devices whose failure disconnects the network.</p>
  <div class="msg"><b>Highest degree:</b>
   {% if r.most %}<span class="path">{{ r.most|join(', ') }}</span>{% else %}none{% endif %}</div>
  <div class="msg"><b>Single point of failure (articulation point):</b>
   {% if r.crit %}<span class="path bad">{{ r.crit|join(', ') }}</span>{% else %}<span class="ok">none</span>{% endif %}</div>
  {% if not r.connected %}<div class="msg warn">Separate components:
   {% for c in r.comps %}[{{ c|join(', ') }}] {% endfor %}</div>{% endif %}
 </div>
</section>

<section class="grid2">
 <div class="box"><h3><span class="tag">C</span>Shortest Path</h3><p class="sub">Shortest route between selected devices.</p>
  <div class="msg" style="text-align:center">
  {% if r.path %}<div class="path">{{ r.path|join(' &rarr; ')|safe }}</div><div style="margin-top:8px">Length: {{ r.path|length - 1 }} connection(s)</div>
  {% else %}{{ r.path_msg or 'No path found' }}{% endif %}</div></div>
 <div class="box"><h3><span class="tag">D</span>Security Analysis</h3><p class="sub">Basic Boolean and logical security rules.</p>
  {% if r.alerts %}
   {% for a in r.alerts %}<div class="msg bad">&#9888; {{ a }}</div>{% endfor %}
  {% else %}<div class="msg"><b class="ok">NETWORK SAFE</b><br>All entered connections are authorized.</div>{% endif %}
  {% for d in r.devices %}<div class="item"><span>{{ d }}</span>
   <span class="{{ {'SAFE':'ok','WARNING':'warn','HIGH RISK':'bad'}[r.status[d]] }}">{{ r.status[d] }}</span></div>{% endfor %}
 </div>
</section>

<section class="box"><h3><span class="tag">E</span>Network Graph</h3><p class="sub">Devices are represented as vertices and connections as edges.</p>
 <div class="vgrid">{% for d in r.devices %}<div class="v"><div class="circle">{{ loop.index }}</div><b>{{ d }}</b>
  <div>{{ r.graph[d]|sort|join(', ') or 'no connections' }}</div></div>{% endfor %}</div></section>

<section class="box chips"><div class="num" style="margin-bottom:6px">DISCRETE MATHEMATICS USED</div>
 <span>Graph Theory</span><span>Sets</span><span>Relations</span><span>Connectivity</span>
 <span>Degree of Vertex</span><span>BFS</span><span>Shortest Path</span><span>Boolean Logic</span></section>
{% endif %}
</main></body></html>"""


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        form = {
            "devices": request.form.get("devices", ""),
            "connections": request.form.get("connections", ""),
            "start": request.form.get("start", ""),
            "dest": request.form.get("dest", ""),
        }
        result = analyze(form["devices"], form["connections"], form["start"], form["dest"])
    else:
        form = {"devices": DEFAULT_DEVICES, "connections": DEFAULT_CONNECTIONS,
                "start": "PC2", "dest": "Server"}
        result = None
    return render_template_string(PAGE, f=form, r=result)


if __name__ == "__main__":
    app.run(debug=True)
