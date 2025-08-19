#!/usr/bin/env python3
import os
import json
from flask import Flask, jsonify, send_from_directory, render_template_string

app = Flask(__name__)

OUTPUT_BASE = os.environ.get("CAMSNIFF_OUTPUT", os.path.join(os.path.dirname(__file__), "..", "output"))

INDEX_HTML = """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>CamSniff Dashboard</title>
  <link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css\">
  <link rel=\"stylesheet\" href=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.css\" integrity=\"sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=\" crossorigin=\"\"/>
  <style>
    body { padding: 1rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 1rem; }
    .card { border: 1px solid #e2e2e2; border-radius: .5rem; padding: .75rem; }
    #map { height: 360px; }
  </style>
  <script src=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.js\" integrity=\"sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=\" crossorigin=\"\"></script>
</head>
<body>
  <main class=\"container\">
    <hgroup>
      <h1>CamSniff Dashboard</h1>
      <p>Real-time camera status, topology, and reports</p>
    </hgroup>
    <section>
      <h3>Cameras</h3>
      <div id=\"cameras\" class=\"grid\"></div>
    </section>
    <section>
      <h3>Topology</h3>
      <pre id=\"topology\">Loading...</pre>
    </section>
    <section>
      <h3>Map</h3>
      <div id=\"map\"></div>
    </section>
    <section>
      <h3>Alerts</h3>
      <pre id=\"alerts\">Loading...</pre>
    </section>
  </main>
  <script>
    async function loadJSON(url) { try { const r = await fetch(url); return r.ok ? r.json() : null; } catch(e) { return null; } }
    async function refresh() {
      const cams = await loadJSON('/api/cameras');
      const topo = await loadJSON('/api/topology');
      const locs = await loadJSON('/api/locations');
      const el = document.getElementById('cameras'); el.innerHTML = '';
      if (cams && cams.length) {
        cams.forEach(c => {
          const d = document.createElement('div'); d.className = 'card';
          const ip = c.ip;
          d.innerHTML = `<strong>${c.ip}:${c.port}</strong><br> ${c.protocol}<br><small>${c.url}</small><br>` +
                        `<img src=\"/screenshot/${ip}/latest\" alt=\"snapshot\" style=\"max-width:100%; margin-top:.5rem\" onerror=\"this.style.display='none'\">` +
                        `<div><a href=\"/api/timeline/${ip}\" target=\"_blank\">Timeline JSON</a></div>`;
          el.appendChild(d);
        });
      } else { el.innerHTML = '<em>No cameras yet</em>'; }
      document.getElementById('topology').textContent = topo ? JSON.stringify(topo, null, 2) : 'No topology data';
      const alerts = await (await fetch('/api/alerts')).text();
      document.getElementById('alerts').textContent = alerts || 'No alerts';

      // Map markers
      if (!window._map) {
        window._map = L.map('map').setView([0,0], 1);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom: 19}).addTo(window._map);
      }
      if (window._markers) { window._markers.forEach(m => m.remove()); }
      window._markers = [];
      if (locs) {
        Object.entries(locs).forEach(([ip, meta]) => {
          if (meta && typeof meta.lat === 'number' && typeof meta.lng === 'number') {
            const m = L.marker([meta.lat, meta.lng]).addTo(window._map).bindPopup(`${ip}${meta.label ? ' - '+meta.label : ''}`);
            window._markers.push(m);
          }
        });
      }
    }
    setInterval(refresh, 5000); refresh();
  </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

@app.route("/api/cameras")
def api_cameras():
    # Find latest result directory
    latest = None
    if os.path.isdir(OUTPUT_BASE):
        entries = [os.path.join(OUTPUT_BASE, d) for d in os.listdir(OUTPUT_BASE) if d.startswith('results_')]
        if entries:
            latest = sorted(entries)[-1]
    cams = []
    if latest:
        p = os.path.join(latest, 'reports', 'summary_' )
        # try list cameras.json as canonical
        cj = os.path.join(latest, 'reports', 'cameras.json')
        if os.path.isfile(cj):
            try:
                data = json.load(open(cj))
                if isinstance(data, list):
                    cams = data
            except Exception:
                pass
    return jsonify(cams)

@app.route("/api/topology")
def api_topology():
    latest = None
    if os.path.isdir(OUTPUT_BASE):
        entries = [os.path.join(OUTPUT_BASE, d) for d in os.listdir(OUTPUT_BASE) if d.startswith('results_')]
        if entries:
            latest = sorted(entries)[-1]
    topo = {}
    if latest:
        tj = os.path.join(latest, 'reports', 'topology.json')
        if os.path.isfile(tj):
            try:
                topo = json.load(open(tj))
            except Exception:
                pass
    return jsonify(topo)
@app.route("/api/locations")
def api_locations():
  latest = None
  if os.path.isdir(OUTPUT_BASE):
    entries = [os.path.join(OUTPUT_BASE, d) for d in os.listdir(OUTPUT_BASE) if d.startswith('results_')]
    if entries:
      latest = sorted(entries)[-1]
  data = {}
  if latest:
    lj = os.path.join(latest, 'reports', 'locations.json')
    if os.path.isfile(lj):
      try:
        data = json.load(open(lj))
      except Exception:
        pass
  return jsonify(data)

@app.route("/screenshot/<ip>/latest")
def latest_screenshot(ip):
  latest = None
  if os.path.isdir(OUTPUT_BASE):
    entries = [os.path.join(OUTPUT_BASE, d) for d in os.listdir(OUTPUT_BASE) if d.startswith('results_')]
    if entries:
      latest = sorted(entries)[-1]
  if latest:
    sdir = os.path.join(latest, 'screenshots')
    if os.path.isdir(sdir):
      # Find files matching snap_<ip>_*.jpg
      files = [f for f in os.listdir(sdir) if f.startswith(f'snap_{ip}_') and f.endswith('.jpg')]
      if files:
        files.sort(reverse=True)
        return send_from_directory(sdir, files[0])
  return ("", 404)

@app.route("/api/timeline/<ip>")
def api_timeline(ip):
  latest = None
  if os.path.isdir(OUTPUT_BASE):
    entries = [os.path.join(OUTPUT_BASE, d) for d in os.listdir(OUTPUT_BASE) if d.startswith('results_')]
    if entries:
      latest = sorted(entries)[-1]
  items = []
  if latest:
    sdir = os.path.join(latest, 'screenshots')
    if os.path.isdir(sdir):
      files = [f for f in os.listdir(sdir) if f.startswith(f'snap_{ip}_') and f.endswith('.jpg')]
      files.sort()
      for f in files[-50:]:
        items.append({"file": f, "url": f"/screenshot/{ip}/latest" if f == files[-1] else None})
  return jsonify(items)

@app.route("/api/alerts")
def api_alerts():
  latest = None
  if os.path.isdir(OUTPUT_BASE):
    entries = [os.path.join(OUTPUT_BASE, d) for d in os.listdir(OUTPUT_BASE) if d.startswith('results_')]
    if entries:
      latest = sorted(entries)[-1]
  if latest:
    af = os.path.join(latest, 'reports', 'alerts.log')
    if os.path.isfile(af):
      try:
        with open(af, 'r') as f:
          return f.read()
      except Exception:
        pass
  return "", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("CAMSNIFF_WEB_PORT", "8088")))
