/**
 * Threat Intelligence Sharing — dashboard client (vanilla JS).
 * API base: same origin when served by Flask; override with localStorage.apiBase for dev.
 */
const API = () => localStorage.getItem("apiBase") || "";

function authHeaders() {
  const t = localStorage.getItem("token");
  const h = { "Content-Type": "application/json" };
  if (t) h["Authorization"] = "Bearer " + t;
  return h;
}

async function api(path, opts = {}) {
  const r = await fetch(API() + path, {
    ...opts,
    headers: { ...authHeaders(), ...(opts.headers || {}) },
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText || "request failed");
  return data;
}

function show(id, on) {
  document.getElementById(id).classList.toggle("hidden", !on);
}

function setMsg(elId, text, ok) {
  const el = document.getElementById(elId);
  if (!el) return;
  el.textContent = text || "";
  el.className = "msg " + (ok ? "ok" : "err");
  el.classList.toggle("hidden", !text);
}

function setView(name) {
  ["view-auth", "view-dash", "view-submit", "view-list", "view-verify"].forEach((id) =>
    show(id, id === "view-" + name)
  );
  document.querySelectorAll("nav button[data-view]").forEach((b) => {
    b.classList.toggle("active", b.dataset.view === name);
  });
}

function updateNav() {
  const t = localStorage.getItem("token");
  const user = JSON.parse(localStorage.getItem("user") || "null");
  show("nav-authed", !!t);
  show("nav-guest", !t);
  const pill = document.getElementById("user-pill");
  if (pill && user) {
    pill.textContent = user.username + " · " + user.role;
  }
  const role = user && user.role;
  show("btn-submit", !!t && (role === "organization" || role === "admin"));
}

function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  setView("auth");
  updateNav();
}

document.getElementById("form-login")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  setMsg("auth-msg", "");
  try {
    const body = {
      username: document.getElementById("login-user").value.trim(),
      password: document.getElementById("login-pass").value,
    };
    const data = await api("/api/login", { method: "POST", body: JSON.stringify(body) });
    localStorage.setItem("token", data.token);
    localStorage.setItem("user", JSON.stringify(data.user));
    updateNav();
    setView("dash");
    loadDashboard();
  } catch (err) {
    setMsg("auth-msg", err.message, false);
  }
});

document.getElementById("form-register")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  setMsg("auth-msg", "");
  try {
    const body = {
      username: document.getElementById("reg-user").value.trim(),
      password: document.getElementById("reg-pass").value,
      organization_name: document.getElementById("reg-org").value.trim(),
      role: document.getElementById("reg-role").value,
    };
    const data = await api("/api/register", { method: "POST", body: JSON.stringify(body) });
    localStorage.setItem("token", data.token);
    localStorage.setItem("user", JSON.stringify(data.user));
    updateNav();
    setView("dash");
    loadDashboard();
  } catch (err) {
    setMsg("auth-msg", err.message, false);
  }
});

document.getElementById("form-threat")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  setMsg("submit-msg", "");
  try {
    const body = {
      organization_name: document.getElementById("t-org").value.trim(),
      attack_title: document.getElementById("t-title").value.trim(),
      attack_type: document.getElementById("t-type").value,
      ioc_ips: document.getElementById("t-ioc-ip").value.trim(),
      ioc_hashes: document.getElementById("t-ioc-hash").value.trim(),
      ioc_domains: document.getElementById("t-ioc-dom").value.trim(),
      attack_description: document.getElementById("t-desc").value.trim(),
      how_it_happened: document.getElementById("t-how").value.trim(),
      impact: document.getElementById("t-impact").value.trim(),
      mitigation: document.getElementById("t-mit").value.trim(),
      date_of_attack: document.getElementById("t-date").value,
    };
    const data = await api("/api/submitThreat", { method: "POST", body: JSON.stringify(body) });
    setMsg(
      "submit-msg",
      "Stored. Hash: " + data.report_hash + (data.tx_hash ? " · Tx: " + data.tx_hash : ""),
      true
    );
    e.target.reset();
  } catch (err) {
    setMsg("submit-msg", err.message, false);
  }
});

let chartTypes = null;

async function loadDashboard() {
  setMsg("dash-msg", "");
  try {
    const s = await api("/api/stats");
    document.getElementById("stat-total").textContent = s.total_reports;
    document.getElementById("stat-chain").textContent = s.on_chain_reports;

    const types = s.attack_types || {};
    const phishingCount = types["Phishing"] || 0;
    const malwareCount = types["Malware"] || 0;
    const ddosCount = types["DDoS"] || 0;

    const elPhishing = document.getElementById("stat-phishing");
    const elMalware = document.getElementById("stat-malware");
    const elDdos = document.getElementById("stat-ddos");
    if (elPhishing) elPhishing.textContent = phishingCount;
    if (elMalware) elMalware.textContent = malwareCount;
    if (elDdos) elDdos.textContent = ddosCount;

    const labels = Object.keys(types);
    const values = labels.map((k) => types[k]);

    const ctx = document.getElementById("chart-types");
    if (ctx && window.Chart) {
      if (chartTypes) chartTypes.destroy();
      chartTypes = new Chart(ctx, {
        type: "doughnut",
        data: {
          labels,
          datasets: [
            {
              data: values,
              backgroundColor: [
                "#3d8bfd",
                "#a78bfa",
                "#34d399",
                "#fbbf24",
                "#f87171",
                "#22d3ee",
                "#94a3b8",
              ],
            },
          ],
        },
        options: {
          plugins: { legend: { labels: { color: "#e8eef7" } } },
        },
      });
    }

    const tbody = document.querySelector("#table-recent tbody");
    if (tbody) {
      tbody.innerHTML = "";
      (s.recent || []).forEach((r) => {
        const tr = document.createElement("tr");
        tr.innerHTML =
          "<td>" +
          escapeHtml(r.attack_title) +
          "</td><td><span class='badge'>" +
          escapeHtml(r.attack_type) +
          "</span></td><td>" +
          escapeHtml(r.organization_name) +
          "</td><td><code class='hash'>" +
          escapeHtml(r.report_hash) +
          "</code></td>";
        tbody.appendChild(tr);
      });
    }
  } catch (err) {
    setMsg("dash-msg", err.message, false);
  }
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

async function loadThreats() {
  setMsg("list-msg", "");
  const filter = document.getElementById("filter-type")?.value || "";
  try {
    const q = filter ? "?attack_type=" + encodeURIComponent(filter) : "";
    const data = await api("/api/getThreats" + q);
    const tbody = document.querySelector("#table-threats tbody");
    tbody.innerHTML = "";
    (data.threats || []).forEach((r) => {
      const tr = document.createElement("tr");
      tr.innerHTML =
        "<td>" +
        escapeHtml(r.attack_title) +
        "</td><td><span class='badge'>" +
        escapeHtml(r.attack_type) +
        "</span></td><td>" +
        escapeHtml(r.organization_name) +
        "</td><td><code class='hash'>" +
        escapeHtml(r.report_hash) +
        "</code></td><td>" +
        escapeHtml(r.ipfs_hash) +
        "</td>";
      tbody.appendChild(tr);
    });
  } catch (err) {
    setMsg("list-msg", err.message, false);
  }
}

document.getElementById("form-verify")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  setMsg("verify-msg", "");
  try {
    const report_hash = document.getElementById("verify-hash").value.trim();
    const data = await api("/api/verifyThreat", {
      method: "POST",
      body: JSON.stringify({ report_hash }),
    });
    const lines = [
      "On-chain verified: " + data.verified_on_chain,
      "In local DB: " + data.found_in_database,
    ];
    setMsg("verify-msg", lines.join(" · "), true);
    const out = document.getElementById("verify-detail");
    if (out) out.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    setMsg("verify-msg", err.message, false);
  }
});

document.getElementById("btn-show-auth")?.addEventListener("click", () => setView("auth"));

document.querySelectorAll("nav button[data-view]").forEach((b) => {
  b.addEventListener("click", () => {
    const v = b.dataset.view;
    if (!localStorage.getItem("token")) {
      setView("auth");
      return;
    }
    setView(v);
    if (v === "dash") loadDashboard();
    if (v === "list") loadThreats();
  });
});

document.getElementById("btn-logout")?.addEventListener("click", logout);

document.getElementById("filter-type")?.addEventListener("change", loadThreats);

updateNav();
if (localStorage.getItem("token")) {
  setView("dash");
  loadDashboard();
} else {
  setView("auth");
}
