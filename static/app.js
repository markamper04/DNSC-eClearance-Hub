// Set to your Render API URL when deploying static/ to Vercel ("" = same origin)
const API_BASE = "";

const state = {
  token: sessionStorage.getItem("hub_token") || "",
  user: null,
};

const $ = (id) => document.getElementById(id);

function announce(msg) {
  $("live-announcer").textContent = msg;
}

function showFlash(msg, isError = false) {
  const el = $("app-flash");
  el.textContent = msg;
  el.className = `notice ${isError ? "notice-error" : "notice-ok"}`;
  el.hidden = false;
  announce(msg);
}

function clearFlash() {
  $("app-flash").hidden = true;
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (options.body && !(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { data = text; }
  if (!res.ok) {
    const err = (data && data.error) || `Request failed (${res.status})`;
    throw new Error(err);
  }
  return data;
}

function badgeHTML(status) {
  const ok = status === "CLEARED";
  const icon = ok
    ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>'
    : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
  return `<span class="badge ${ok ? "badge-ok" : "badge-hold"}">${icon} ${status}</span>`;
}

function esc(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderNav(role) {
  const items = role === "student"
    ? [{ id: "panel-student", label: "My Clearance" }]
    : role === "staff"
      ? [{ id: "panel-staff", label: "Clearance Desk" }]
      : [{ id: "panel-admin", label: "Admin Console" }, { id: "panel-staff", label: "Clearance Desk" }];

  const buildList = (container, isMobile) => {
    container.innerHTML = "";
    items.forEach((item, idx) => {
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = isMobile ? "btn-secondary btn-full" : "nav-btn";
      if (idx === 0) btn.setAttribute("aria-current", "page");
      btn.textContent = item.label;
      btn.addEventListener("click", () => {
        switchPanel(item.id);
        if (isMobile) $("mobile-nav").hidePopover();
      });
      li.appendChild(btn);
      container.appendChild(li);
    });
  };

  buildList($("sidebar-nav"), false);
  buildList($("mobile-nav-list"), true);
  switchPanel(items[0].id);
}

function switchPanel(panelId) {
  ["panel-student", "panel-staff", "panel-admin"].forEach((id) => {
    $(id).hidden = id !== panelId;
  });
  $("sidebar-nav").querySelectorAll("button").forEach((b) => {
    const active = (b.textContent === "My Clearance" && panelId === "panel-student")
      || (b.textContent === "Clearance Desk" && panelId === "panel-staff")
      || (b.textContent === "Admin Console" && panelId === "panel-admin");
    if (active) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  if (panelId === "panel-student") loadStudentView();
  if (panelId === "panel-staff") loadStaffView();
  if (panelId === "panel-admin") loadAdminView();
}

async function loadStudentView() {
  try {
    const data = await api("/api/clearance/me");
    const s = data.student;
    $("student-meta").textContent = `${s.name} (${s.student_id} · ${s.program} ${s.year}) · Deadline: ${data.deadline}`;
    $("student-overall-badge").outerHTML = badgeHTML(data.overall_status).replace("<span ", '<span id="student-overall-badge" ');
    $("student-summary-note").textContent = data.overall_status === "CLEARED"
      ? "All 4 offices cleared. Your verifiable QR slip is ready below."
      : "Resolve any HOLD items below before your QR slip can be issued.";

    $("student-offices-body").innerHTML = data.offices.map((o) => `
      <tr>
        <th>${esc(o.office)}</th>
        <td data-label="Status">${badgeHTML(o.status)}</td>
        <td data-label="Remarks">${esc(o.reason || "Cleared")}</td>
        <td data-label="Updated">${esc(o.updated_at.slice(0, 10))}</td>
      </tr>
    `).join("");

    if (data.overall_status === "CLEARED") {
      const slip = await api("/api/clearance/slip");
      renderQrSlip(slip.slip_token);
    } else {
      $("slip-content").innerHTML = '<p class="meta-line">QR slip is locked until all 4 offices show CLEARED.</p>';
    }
  } catch (err) {
    showFlash(err.message, true);
  }
}

function renderQrSlip(token) {
  const wrap = $("slip-content");
  let qrHtml = "";
  if (typeof window.qrcode === "function") {
    const qr = window.qrcode(0, "M");
    qr.addData(token);
    qr.make();
    qrHtml = `<div class="qr-frame">${qr.createSvgTag(4, 2)}</div>`;
  }
  wrap.innerHTML = `
    <div class="qr-wrap">
      ${qrHtml}
      <div>
        <p style="margin:0 0 0.5rem;font-weight:600;">Signed Clearance Token (verifiable by any office):</p>
        <div class="token-box">${esc(token)}</div>
      </div>
    </div>
  `;
}

async function loadStaffView(query = "") {
  const office = state.user.office;
  $("staff-meta").textContent = office ? `Assigned office: ${office}` : "Admin override: all offices";
  const select = $("staff-office");
  if (office) {
    select.value = office;
    select.disabled = true;
  } else {
    select.disabled = false;
  }
  try {
    const qs = query ? `?q=${encodeURIComponent(query)}` : "";
    const data = await api(`/api/staff/students${qs}`);
    $("staff-students-body").innerHTML = data.students.map((s) => `
      <tr>
        <th>${esc(s.student_id)}</th>
        <td data-label="Name">${esc(s.name)}</td>
        <td data-label="Program">${esc(s.program)} ${esc(s.year)}</td>
        <td data-label="Overall">${badgeHTML(s.overall_status)}</td>
        <td data-label="Offices">${s.offices.map((o) => `${esc(o.office)}: ${esc(o.status)}`).join(" · ")}</td>
      </tr>
    `).join("");
  } catch (err) {
    showFlash(err.message, true);
  }
}

async function loadAdminView() {
  try {
    const data = await api("/api/admin/audit");
    $("admin-audit-body").innerHTML = data.audit_log.map((row) => `
      <tr>
        <th>${esc(row.timestamp.replace("T", " ").slice(0, 19))}</th>
        <td data-label="Who">${esc(row.who)}</td>
        <td data-label="Action">${esc(row.action)}</td>
        <td data-label="Target">${esc(row.target)}</td>
        <td data-label="Details">${esc(row.details)}</td>
      </tr>
    `).join("");
  } catch (err) {
    showFlash(err.message, true);
  }
}

async function bootSession() {
  if (!state.token) {
    $("view-login").hidden = false;
    $("view-app").hidden = true;
    return;
  }
  try {
    const data = await api("/api/auth/me");
    state.user = data.user;
    $("view-login").hidden = true;
    $("view-app").hidden = false;
    $("user-label").textContent = `${state.user.sub} (${state.user.role})`;
    $("sidebar-role-label").textContent = `Signed in as ${state.user.role}`;
    renderNav(state.user.role);
  } catch {
    sessionStorage.removeItem("hub_token");
    state.token = "";
    $("view-login").hidden = false;
    $("view-app").hidden = true;
  }
}

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  if (!form.checkValidity()) {
    form.querySelector(":invalid")?.focus();
    return;
  }
  const errBox = $("login-error");
  errBox.hidden = true;
  $("login-submit").disabled = true;
  try {
    const data = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("login-username").value.trim(),
        password: $("login-password").value,
      }),
    });
    state.token = data.token;
    sessionStorage.setItem("hub_token", data.token);
    await bootSession();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  } finally {
    $("login-submit").disabled = false;
  }
});

$("logout-btn").addEventListener("click", () => {
  sessionStorage.removeItem("hub_token");
  state.token = "";
  state.user = null;
  clearFlash();
  bootSession();
});

$("sidebar-toggle").addEventListener("click", () => {
  if (window.matchMedia("(max-width: 760px)").matches) {
    $("mobile-nav").togglePopover();
    return;
  }
  const collapsed = $("view-app").classList.toggle("sidebar-collapsed");
  $("sidebar-toggle").setAttribute("aria-expanded", String(!collapsed));
});

$("staff-update-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!e.target.checkValidity()) { e.target.querySelector(":invalid")?.focus(); return; }
  try {
    await api("/api/staff/clearance", {
      method: "POST",
      body: JSON.stringify({
        student_id: $("staff-sid").value.trim(),
        office: $("staff-office").value,
        status: $("staff-status").value,
        reason: $("staff-reason").value.trim(),
      }),
    });
    showFlash("Clearance status updated.");
    loadStaffView($("staff-search-q").value.trim());
  } catch (err) {
    showFlash(err.message, true);
  }
});

$("staff-search-form").addEventListener("submit", (e) => {
  e.preventDefault();
  loadStaffView($("staff-search-q").value.trim());
});

$("verify-slip-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const tok = $("verify-token-input").value.trim();
  if (!tok) return;
  const out = $("verify-result");
  try {
    const res = await api(`/api/clearance/verify?token=${encodeURIComponent(tok)}`);
    out.textContent = `VALID: ${res.student_id} (${res.overall_status})`;
    out.className = "notice notice-ok";
    out.hidden = false;
  } catch (err) {
    out.textContent = `INVALID: ${err.message}`;
    out.className = "notice notice-error";
    out.hidden = false;
  }
});

$("sync-registrar-btn").addEventListener("click", async () => {
  try {
    const res = await api("/api/admin/sync-registrar", { method: "POST" });
    showFlash(`Synced ${res.synced} students from Registrar API.`);
    loadAdminView();
  } catch (err) {
    showFlash(err.message, true);
  }
});

document.querySelectorAll("[data-export]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const fmt = btn.dataset.export;
    try {
      const res = await fetch(`${API_BASE}/api/admin/reports?format=${fmt}`, {
        headers: { Authorization: `Bearer ${state.token}` },
      });
      if (!res.ok) throw new Error(`Export failed (${res.status})`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `clearance_report.${fmt}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      showFlash(err.message, true);
    }
  });
});

bootSession();
