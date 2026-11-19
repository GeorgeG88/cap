/* Dashboard charts. Data comes from /api/stats as JSON (no inline scripts: CSP).
 *
 * How it works:
 *   1. Find the #dash element on the dashboard page. Its data attributes say
 *      where to get the statistics and whether live monitoring is running.
 *   2. Fetch the statistics as JSON from the server.
 *   3. Draw four charts with Chart.js (traffic over time, alerts by rule,
 *      top source IPs, top destination ports).
 *   4. While live monitoring runs, fetch again every 15 seconds and update
 *      the existing charts in place.
 *
 * The whole file is wrapped in a function that runs immediately, so its
 * variables do not leak into the rest of the page.
 */
(function () {
  "use strict";
  const root = document.getElementById("dash");
  // Not on the dashboard, or Chart.js failed to load: do nothing.
  if (!root || typeof Chart === "undefined") return;

  // Chart colours are taken from the CSS variables in app.css, so the
  // stylesheet is the single place where the colours are defined.
  const css = getComputedStyle(document.documentElement);
  const color = (name) => css.getPropertyValue(name).trim();
  const C = {
    allow: color("--c-allow"), deny: color("--c-deny"), other: color("--c-other"),
    accent: color("--c-accent"), port: color("--c-port"), grid: color("--c-grid"), text: color("--c-muted"),
  };

  // Default look for every chart: dark theme colours, page font, short animations.
  Chart.defaults.color = C.text;
  Chart.defaults.borderColor = C.grid;
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  Chart.defaults.font.size = 12;
  Chart.defaults.plugins.legend.labels.boxWidth = 10;
  Chart.defaults.animation.duration = 250;

  // Chart objects already drawn, by canvas id.
  const charts = {};

  // Create a chart the first time; on later refreshes only swap its data.
  // Updating in place avoids flicker and keeps tooltips working.
  function upsert(id, config) {
    if (charts[id]) {
      charts[id].data = config.data;
      charts[id].update("none");
      return;
    }
    const el = document.getElementById(id);
    if (el) charts[id] = new Chart(el, config);
  }

  // Settings for a horizontal bar chart (used for the three "top" charts).
  function hbar(labels, values, barColor, label) {
    return {
      type: "bar",
      data: { labels, datasets: [{ label, data: values, backgroundColor: barColor, borderRadius: 3, maxBarThickness: 18 }] },
      options: {
        indexAxis: "y", maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } },
      },
    };
  }

  // Draw or update every chart from one statistics object (s).
  function render(s) {
    document.getElementById("tl-unit").textContent = "per " + s.timeline.unit;
    // Stacked bars: denied, allowed and audit events per minute/hour/day.
    upsert("chart-timeline", {
      type: "bar",
      data: {
        labels: s.timeline.labels,
        datasets: [
          { label: "Denied", data: s.timeline.deny, backgroundColor: C.deny, stack: "a" },
          { label: "Allowed", data: s.timeline.allow, backgroundColor: C.allow, stack: "a" },
          { label: "Audit", data: s.timeline.other, backgroundColor: C.other, stack: "a" },
        ],
      },
      options: {
        maintainAspectRatio: false, interaction: { mode: "index", intersect: false },
        scales: {
          x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 12, maxRotation: 0 } },
          y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } },
        },
        plugins: { legend: { position: "top", align: "end" } },
      },
    });
    upsert("chart-rules", hbar(s.alerts.by_rule.map((r) => r.rule), s.alerts.by_rule.map((r) => r.count), C.accent, "Alerts"));
    upsert("chart-sources", hbar(s.top_sources.map((r) => r.ip), s.top_sources.map((r) => r.count), C.allow, "Events"));
    upsert("chart-ports", hbar(s.top_ports.map((r) => String(r.port)), s.top_ports.map((r) => r.count), C.port, "Events"));
  }

  // Get the statistics from the server and redraw. The session cookie is
  // sent along ("same-origin"), because /api/stats requires a login.
  // A failed refresh is only logged; the charts keep their last data.
  function load() {
    fetch(root.dataset.statsUrl, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
      .then(render)
      .catch((e) => console.warn("stats refresh failed", e));
  }

  load();
  // Auto-refresh only during live monitoring; uploaded data does not change.
  if (root.dataset.live === "1") setInterval(load, 15000);
})();
