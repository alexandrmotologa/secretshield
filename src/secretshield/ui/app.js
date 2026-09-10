// SecretShield Web Dashboard JavaScript Controller

document.addEventListener("DOMContentLoaded", () => {
  // Navigation Tabs
  const navItems = document.querySelectorAll(".nav-item");
  const tabPanes = document.querySelectorAll(".tab-pane");
  const pageTitle = document.getElementById("page-title");

  const titles = {
    overview: "Real-Time Proxy Overview",
    vault: "Encrypted Credential Vault",
    budgets: "Service Budgets & Quotas",
    audit: "Hash-Chained Audit Explorer",
    playground: "Interactive Request Playground",
  };

  navItems.forEach((btn) => {
    btn.addEventListener("click", () => {
      navItems.forEach((b) => b.classList.remove("active"));
      tabPanes.forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const tabId = btn.getAttribute("data-tab");
      document.getElementById(`tab-${tabId}`).classList.add("active");
      pageTitle.textContent = titles[tabId] || "Dashboard";

      if (tabId === "vault") loadProfiles();
      if (tabId === "audit") loadAudit();
    });
  });

  // Telemetry Fetching
  async function fetchTelemetry() {
    try {
      const res = await fetch("/admin/metrics");
      if (!res.ok) return;
      const data = await res.json();

      // Update counters
      const events = data.recent_events || [];
      const budgets = data.budgets || {};
      const cache = data.cache || { hits: 0, misses: 0, hit_ratio_percent: 0 };

      document.getElementById("stat-profiles").textContent = Object.keys(budgets).length || "1";
      document.getElementById("stat-requests").textContent = events.length;
      document.getElementById("stat-cache").textContent = `${cache.hit_ratio_percent}%`;
      document.getElementById("stat-cache-sub").textContent = `${cache.hits} hits / ${cache.misses} misses`;

      // Live Request Stream
      renderStreamTable(events);

      // Budgets Side List
      renderBudgets(budgets);

      // Security Alerts
      renderAlerts(events);
    } catch (err) {
      console.warn("Failed to poll telemetry:", err);
    }
  }

  function renderStreamTable(events) {
    const tbody = document.getElementById("stream-body");
    if (!events || events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">Awaiting traffic...</td></tr>';
      return;
    }

    tbody.innerHTML = events.slice(-10).reverse().map((ev) => {
      const statusClass = ev.status < 400 ? "text-success" : (ev.status < 500 ? "text-warning" : "text-danger");
      return `
        <tr>
          <td>${ev.timestamp || "--:--:--"}</td>
          <td>${ev.service_id || "unknown"}</td>
          <td>${ev.profile || "-"}</td>
          <td>${ev.method || "GET"}</td>
          <td class="${statusClass}">${ev.status}</td>
          <td>${ev.latency_ms ? ev.latency_ms.toFixed(1) + " ms" : "-"}</td>
          <td>${ev.cost_usd ? "$" + ev.cost_usd.toFixed(4) : "$0.0000"}</td>
        </tr>
      `;
    }).join("");
  }

  function renderBudgets(budgets) {
    const list = document.getElementById("overview-budgets-list");
    const fullList = document.getElementById("full-budgets-view");
    const keys = Object.keys(budgets);

    if (keys.length === 0) {
      list.innerHTML = '<p class="text-muted">No active budget limits configured.</p>';
      if (fullList) fullList.innerHTML = '<p class="text-muted">No budgets configured.</p>';
      return;
    }

    const html = keys.map((sid) => {
      const b = budgets[sid];
      const pct = b.daily_percent || 0;
      const fillColor = pct < 70 ? "#10B981" : (pct < 90 ? "#F59E0B" : "#EF4444");
      return `
        <div class="budget-item">
          <div class="budget-label-row">
            <span><strong>${sid}</strong></span>
            <span>$${b.daily_spent.toFixed(2)} / $${b.daily_limit.toFixed(2)} (${pct.toFixed(1)}%)</span>
          </div>
          <div class="progress-bar-bg">
            <div class="progress-bar-fill" style="width: ${Math.min(pct, 100)}%; background-color: ${fillColor};"></div>
          </div>
        </div>
      `;
    }).join("");

    list.innerHTML = html;
    if (fullList) fullList.innerHTML = html;
  }

  function renderAlerts(events) {
    const alertsBox = document.getElementById("overview-alerts-list");
    const alerts = events.filter((e) => [401, 403, 429].includes(e.status));

    if (alerts.length === 0) {
      alertsBox.innerHTML = '<div class="alert-clean">✅ Zero Security Violations Detected</div>';
      return;
    }

    alertsBox.innerHTML = alerts.slice(-4).reverse().map((a) => {
      const badge = a.status === 401 ? "[AUTH FAIL]" : (a.status === 403 ? "[FORBIDDEN]" : "[QUOTA EXCEEDED]");
      return `
        <div class="alert-item">
          <strong>${badge}</strong> ${a.service_id} &rarr; ${a.profile}: ${a.detail || "Request blocked"}
        </div>
      `;
    }).join("");
  }

  // Profiles Manager
  async function loadProfiles() {
    try {
      const res = await fetch("/admin/profiles");
      if (!res.ok) return;
      const profiles = await res.json();
      const tbody = document.getElementById("profiles-body");

      if (profiles.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No profiles found in vault.</td></tr>';
        return;
      }

      tbody.innerHTML = profiles.map((p) => `
        <tr>
          <td><strong>${p.name}</strong></td>
          <td>${p.base_url}</td>
          <td>${p.domains && p.domains.length > 0 ? p.domains.join(", ") : "-"}</td>
          <td><span class="badge badge-cipher">${p.injection_type}</span></td>
          <td>v${p.version || 1}</td>
          <td><code>${p.secret_preview}</code></td>
          <td>${p.updated_at ? p.updated_at.slice(0, 19) : "-"}</td>
          <td><button class="btn btn-outline btn-sm" onclick="deleteProfile('${p.name}')">Delete</button></td>
        </tr>
      `).join("");
    } catch (e) {
      console.error(e);
    }
  }

  // Audit Ledger
  async function loadAudit() {
    try {
      const res = await fetch("/admin/audit/recent");
      if (!res.ok) return;
      const records = await res.json();
      const tbody = document.getElementById("audit-body");

      if (records.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No audit records recorded yet.</td></tr>';
        return;
      }

      tbody.innerHTML = records.map((r) => `
        <tr>
          <td>#${r.id}</td>
          <td>${r.timestamp.slice(0, 19)}</td>
          <td><strong>${r.service_id}</strong></td>
          <td>${r.profile_name}${r.path}</td>
          <td><span class="badge ${r.status_code < 400 ? 'badge-success' : 'badge-danger'}">${r.status_code}</span></td>
          <td>$${r.cost_usd.toFixed(4)}</td>
          <td><code>${r.record_hash.slice(0, 16)}...</code></td>
          <td><code>${r.prev_hash.slice(0, 12)}...</code></td>
        </tr>
      `).join("");
    } catch (e) {
      console.error(e);
    }
  }

  // Verify Audit Chain
  document.getElementById("btn-verify-audit-chain")?.addEventListener("click", async () => {
    const banner = document.getElementById("audit-verify-banner");
    banner.style.display = "block";
    banner.className = "alert-item";
    banner.textContent = "Verifying cryptographic SHA-256 chain...";

    try {
      const res = await fetch("/admin/audit/verify", { method: "POST" });
      const data = await res.json();
      if (data.is_valid) {
        banner.className = "alert-clean";
        banner.textContent = `✓ Audit chain is 100% VALID (${data.verified_count} records verified). No tampering detected.`;
      } else {
        banner.className = "alert-item text-danger";
        banner.textContent = `❌ AUDIT CHAIN COMPROMISED: ${data.error}`;
      }
    } catch (e) {
      banner.textContent = "Verification request failed.";
    }
  });

  // Playground Request Simulator
  document.getElementById("btn-send-sim")?.addEventListener("click", async () => {
    const method = document.getElementById("pg-method").value;
    const profile = document.getElementById("pg-profile").value.trim();
    const path = document.getElementById("pg-path").value.trim();
    const serviceId = document.getElementById("pg-service-id").value.trim();
    const token = document.getElementById("pg-service-token").value.trim();
    const body = document.getElementById("pg-body").value.trim();

    const resultBox = document.getElementById("pg-result-box");
    const statusPill = document.getElementById("pg-result-status");
    const timeLabel = document.getElementById("pg-result-time");
    const contentBox = document.getElementById("pg-result-content");

    resultBox.style.display = "block";
    statusPill.textContent = "Sending...";
    contentBox.textContent = "Waiting for proxy response...";

    const headers = { "Content-Type": "application/json" };
    if (serviceId) headers["X-Service-Id"] = serviceId;
    if (token) headers["X-Service-Token"] = token;

    const startTime = performance.now();
    try {
      const res = await fetch(`/proxy/${profile}/${path}`, {
        method: method,
        headers: headers,
        body: ["GET", "HEAD"].includes(method) ? undefined : body,
      });

      const latency = (performance.now() - startTime).toFixed(1);
      statusPill.textContent = `${res.status} ${res.statusText}`;
      statusPill.className = `badge ${res.status < 400 ? 'badge-success' : 'badge-danger'}`;
      timeLabel.textContent = `(${latency} ms)`;

      const text = await res.text();
      try {
        contentBox.textContent = JSON.stringify(JSON.parse(text), null, 2);
      } catch {
        contentBox.textContent = text;
      }
      fetchTelemetry();
    } catch (err) {
      statusPill.textContent = "Network Error";
      statusPill.className = "badge badge-danger";
      contentBox.textContent = err.toString();
    }
  });

  // Modal Dialog handling
  const modal = document.getElementById("modal-create-profile");
  document.getElementById("btn-open-create-profile")?.addEventListener("click", () => {
    modal.style.display = "flex";
  });
  document.getElementById("btn-close-modal")?.addEventListener("click", () => {
    modal.style.display = "none";
  });
  document.getElementById("btn-cancel-modal")?.addEventListener("click", () => {
    modal.style.display = "none";
  });

  document.getElementById("btn-save-modal")?.addEventListener("click", async () => {
    const name = document.getElementById("modal-name").value.trim();
    const baseUrl = document.getElementById("modal-base-url").value.trim();
    const secret = document.getElementById("modal-secret").value.trim();
    const type = document.getElementById("modal-type").value;
    const header = document.getElementById("modal-header-name").value.trim();

    if (!name || !baseUrl || !secret) {
      alert("Please fill in Name, Base URL, and Secret.");
      return;
    }

    try {
      const res = await fetch("/admin/profiles", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name,
          base_url: baseUrl,
          secret: secret,
          injection_type: type,
          header_name: header,
        }),
      });
      if (res.ok) {
        modal.style.display = "none";
        loadProfiles();
      } else {
        const err = await res.json();
        alert("Failed to save: " + (err.detail || "unknown error"));
      }
    } catch (e) {
      alert("Error saving profile");
    }
  });

  // Global Delete Profile
  window.deleteProfile = async (name) => {
    if (!confirm(`Are you sure you want to delete profile '${name}'?`)) return;
    try {
      const res = await fetch(`/admin/profiles/${name}`, { method: "DELETE" });
      if (res.ok) loadProfiles();
    } catch (e) {
      console.error(e);
    }
  };

  // Refresh button
  document.getElementById("btn-refresh")?.addEventListener("click", fetchTelemetry);

  // Initial poll & recurring interval
  fetchTelemetry();
  setInterval(fetchTelemetry, 3000);
});
