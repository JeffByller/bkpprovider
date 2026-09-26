// ---------- API helper ----------

async function api(path, options) {
    const res = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, options));
    if (res.status === 401) {
        window.location.href = "/login";
        throw new Error("not authenticated");
    }
    let data = null;
    try { data = await res.json(); } catch (e) { /* no body */ }
    if (!res.ok) {
        const msg = (data && data.detail) || `Erro (${res.status})`;
        throw new Error(msg);
    }
    return data;
}

function apiGet(path) { return api(path); }
function apiPost(path, body) { return api(path, { method: "POST", body: JSON.stringify(body || {}) }); }
function apiPut(path, body) { return api(path, { method: "PUT", body: JSON.stringify(body || {}) }); }
function apiDelete(path) { return api(path, { method: "DELETE" }); }

// ---------- Tabs ----------

function initTabs() {
    document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.addEventListener("click", () => switchTab(btn.dataset.tab));
    });
}

function switchTab(tabId) {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.toggle("active", b.dataset.tab === tabId));
    document.querySelectorAll(".tab-content").forEach(s => s.classList.toggle("active", s.id === tabId));
    try { localStorage.setItem("bkpprovider_tab", tabId); } catch (e) { /* ignore */ }
}

// ---------- Modal helpers ----------

function openModal(id) { document.getElementById(id).hidden = false; }
function closeModal(id) { document.getElementById(id).hidden = true; }

function closeAllModals() {
    document.querySelectorAll(".modal-overlay").forEach(overlay => {
        overlay.hidden = true;
    });
}

// Close modals on ESC key or when clicking backdrop overlay
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
        closeAllModals();
    }
});

document.addEventListener("click", (e) => {
    if (e.target.classList.contains("modal-overlay")) {
        e.target.hidden = true;
    }
});

function openTargetModal(target) {
    const form = document.getElementById("target-form");
    form.reset();
    form.id.value = target ? target.id : "";
    if (target) {
        form.name.value = target.name;
        form.ip.value = target.ip;
        document.getElementById("target-modal-title").textContent = "Editar IP";
    } else {
        document.getElementById("target-modal-title").textContent = "Novo IP para monitorar";
    }
    openModal("target-modal");
}

function openDeviceModal(device) {
    const form = document.getElementById("device-form");
    form.reset();
    form.id.value = device ? device.id : "";
    const passwordInput = form.password;
    const hint = document.getElementById("device-password-hint");
    if (device) {
        form.name.value = device.name;
        form.ip.value = device.ip;
        form.port.value = device.port;
        form.username.value = device.username;
        passwordInput.required = false;
        hint.hidden = false;
        document.getElementById("device-modal-title").textContent = "Editar Mikrotik";
    } else {
        form.port.value = 22;
        passwordInput.required = true;
        hint.hidden = true;
        document.getElementById("device-modal-title").textContent = "Novo Mikrotik";
    }
    openModal("device-modal");
}

// ---------- Sparkline (pure inline SVG, no libs) ----------

function renderSparkline(history) {
    if (!history || history.length === 0) {
        return '<span class="sparkline-empty">sem dados</span>';
    }
    const width = 100, height = 28;
    const n = history.length;
    const dx = n > 1 ? width / (n - 1) : 0;
    const latencies = history.filter(h => h.ok && h.latency != null).map(h => h.latency);
    const minL = latencies.length ? Math.min(...latencies) : 0;
    const maxL = latencies.length ? Math.max(...latencies) : 1;
    const range = (maxL - minL) || 1;

    let pathParts = [];
    let penDown = false;
    let circles = [];

    history.forEach((h, i) => {
        const x = (i * dx).toFixed(1);
        if (h.ok && h.latency != null) {
            const y = (height - 4 - ((h.latency - minL) / range) * (height - 8)).toFixed(1);
            pathParts.push((penDown ? "L" : "M") + x + "," + y);
            penDown = true;
        } else {
            penDown = false;
            circles.push(`<circle cx="${x}" cy="${height - 3}" r="2" fill="#dc3545"></circle>`);
        }
    });

    const path = pathParts.length
        ? `<path d="${pathParts.join(" ")}" fill="none" stroke="#007bff" stroke-width="1.5"></path>`
        : "";

    return `<svg class="sparkline" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">${path}${circles.join("")}</svg>`;
}

// ---------- Targets (Monitoramento) ----------

function statusBadge(t) {
    if (!t.active) return '<span class="badge badge-inactive">INATIVO</span>';
    if (t.status === "UP") return '<span class="badge badge-up">UP</span>';
    return '<span class="badge badge-down">DOWN</span>';
}

function fmtLatency(v) { return v == null ? "-" : `${Number(v).toFixed(1)} ms`; }
function fmtPct(v) { return v == null ? "-" : `${Number(v).toFixed(1)}%`; }

async function refreshTargets() {
    const targets = await apiGet("/api/targets");
    const tbody = document.getElementById("targets-tbody");
    tbody.innerHTML = targets.map(t => `
        <tr class="${t.active ? "" : "row-inactive"}">
            <td>${escapeHtml(t.name)}</td>
            <td>${escapeHtml(t.ip)}</td>
            <td>${statusBadge(t)}</td>
            <td>${fmtLatency(t.latency_ms)}</td>
            <td>${fmtLatency(t.avg_latency_ms)}</td>
            <td>${fmtPct(t.packet_loss_pct)}</td>
            <td>${renderSparkline(t.history)}</td>
            <td>${t.last_check || "-"}</td>
            <td class="actions-cell">
                <button class="btn btn-primary btn-sm" onclick='openTargetModal(${JSON.stringify(t)})'>Editar</button>
                <button class="btn ${t.active ? "btn-warning" : "btn-info"} btn-sm" onclick="toggleTarget(${t.id})">${t.active ? "Inativar" : "Ativar"}</button>
                <button class="btn btn-danger btn-sm" onclick="deleteTarget(${t.id}, '${escapeHtml(t.name)}')">Remover</button>
            </td>
        </tr>
    `).join("");
}

async function toggleTarget(id) {
    await apiPost(`/api/targets/${id}/toggle`);
    refreshTargets();
}

async function deleteTarget(id, name) {
    if (!confirm(`Remover o IP monitorado "${name}"?`)) return;
    await apiDelete(`/api/targets/${id}`);
    refreshTargets();
}

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("target-form");
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const id = form.id.value;
        const body = { name: form.name.value.trim(), ip: form.ip.value.trim() };
        try {
            if (id) await apiPut(`/api/targets/${id}`, body);
            else await apiPost("/api/targets", body);
            closeModal("target-modal");
            refreshTargets();
        } catch (err) {
            alert(err.message);
        }
    });
});

// ---------- Mikrotik devices (Backups) ----------

function deviceStatusClass(status) {
    if (status === "SUCCESS") return "badge-up";
    if (status === "PENDING") return "badge-inactive";
    return "badge-down";
}

function renderFileOptions(deviceId, files) {
    if (!files || files.length === 0) {
        return '<span class="sparkline-empty">Nenhum backup</span>';
    }
    const options = files.map(f => `<option value="${escapeHtml(f)}">${escapeHtml(f)}</option>`).join("");
    return `
        <select id="file-select-${deviceId}">${options}</select>
        <button type="button" class="btn btn-info btn-sm" onclick="downloadBackup(${deviceId})">Baixar</button>
    `;
}

async function refreshDevices() {
    const devices = await apiGet("/api/devices");
    const tbody = document.getElementById("devices-tbody");
    tbody.innerHTML = devices.map(d => `
        <tr>
            <td>${escapeHtml(d.name)}</td>
            <td>${escapeHtml(d.ip)}:${d.port}</td>
            <td>${escapeHtml(d.username)}</td>
            <td>${d.last_backup || "-"}</td>
            <td><span class="badge ${deviceStatusClass(d.last_status)}">${escapeHtml(d.last_status)}</span></td>
            <td>${renderFileOptions(d.id, d.files)}</td>
            <td class="actions-cell">
                <button class="btn btn-primary btn-sm" onclick="triggerBackup(${d.id})">Backup agora</button>
                <button class="btn btn-primary btn-sm" onclick='openDeviceModal(${JSON.stringify({ id: d.id, name: d.name, ip: d.ip, port: d.port, username: d.username })})'>Editar</button>
                <button class="btn btn-danger btn-sm" onclick="deleteDevice(${d.id}, '${escapeHtml(d.name)}')">Remover</button>
            </td>
        </tr>
    `).join("");
}

async function triggerBackup(id) {
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = "Executando...";
    try {
        const result = await apiPost(`/api/devices/${id}/backup-now`);
        alert(result.ok ? "Backup realizado com sucesso!" : `Falha no backup: ${result.message}`);
    } finally {
        refreshDevices();
    }
}

async function deleteDevice(id, name) {
    if (!confirm(`Remover o dispositivo "${name}"?`)) return;
    await apiDelete(`/api/devices/${id}`);
    refreshDevices();
}

function downloadBackup(deviceId) {
    const select = document.getElementById(`file-select-${deviceId}`);
    const filename = select.value;
    const password = prompt("Digite a senha para autorizar o download do backup:");
    if (password) {
        window.location.href = `/mikrotik/download?filename=${encodeURIComponent(filename)}&password=${encodeURIComponent(password)}`;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("device-form");
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const id = form.id.value;
        const body = {
            name: form.name.value.trim(),
            ip: form.ip.value.trim(),
            port: parseInt(form.port.value, 10) || 22,
            username: form.username.value.trim(),
            password: form.password.value,
        };
        try {
            if (id) await apiPut(`/api/devices/${id}`, body);
            else await apiPost("/api/devices", body);
            closeModal("device-modal");
            refreshDevices();
        } catch (err) {
            alert(err.message);
        }
    });
});

// ---------- Dashboard summary ----------

async function refreshSummary() {
    const s = await apiGet("/api/summary");
    document.getElementById("stat-targets-total").textContent = s.targets_total;
    document.getElementById("stat-targets-up").textContent = s.targets_up;
    document.getElementById("stat-targets-down").textContent = s.targets_down;
    document.getElementById("stat-avg-latency").textContent = fmtLatency(s.avg_latency_ms);
    document.getElementById("stat-devices-total").textContent = s.devices_total;
    document.getElementById("stat-backups-ok").textContent = s.backups_ok_today;
    document.getElementById("stat-backups-failed").textContent = s.backups_failed_today;
}

// ---------- Settings ----------

async function loadSettings() {
    const s = await apiGet("/api/settings");
    ["telegram-form", "monitoring-form", "backup-form"].forEach(formId => {
        const form = document.getElementById(formId);
        Array.from(form.elements).forEach(el => {
            if (el.name && s[el.name] !== undefined) el.value = s[el.name];
        });
    });
}

async function saveAllSettings() {
    const payload = {};
    ["telegram-form", "monitoring-form", "backup-form"].forEach(formId => {
        const form = document.getElementById(formId);
        Array.from(form.elements).forEach(el => {
            if (el.name) payload[el.name] = el.value;
        });
    });
    try {
        await apiPost("/api/settings", payload);
        const msg = document.getElementById("settings-saved-msg");
        msg.hidden = false;
        setTimeout(() => { msg.hidden = true; }, 2500);
    } catch (err) {
        alert(err.message);
    }
}

// ---------- Utils ----------

function escapeHtml(str) {
    if (str == null) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

// ---------- Bootstrap ----------

let pollTimer = null;

async function refreshAll() {
    await Promise.all([refreshTargets(), refreshDevices(), refreshSummary()]);
}

document.addEventListener("DOMContentLoaded", async () => {
    initTabs();
    try {
        const savedTab = localStorage.getItem("bkpprovider_tab") || localStorage.getItem("meuprovedor_tab");
        if (savedTab && document.getElementById(savedTab)) switchTab(savedTab);
    } catch (e) { /* ignore */ }

    await loadSettings();
    await refreshAll();

    const settings = await apiGet("/api/settings");
    const intervalMs = Math.max(parseInt(settings.ping_interval_seconds, 10) || 15, 5) * 1000;
    pollTimer = setInterval(refreshAll, intervalMs);
});
