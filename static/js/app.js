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

// ---------- License Management ----------

let currentLicenseLogsId = null;

async function refreshLicenses() {
    const tbody = document.getElementById("licenses-tbody");
    if (!tbody) return;
    try {
        const licenses = await apiGet("/api/licenses");
        if (licenses.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #888; padding: 20px;">Nenhuma licença cadastrada. Clique em "+ Nova Licença" para começar.</td></tr>`;
            return;
        }

        tbody.innerHTML = licenses.map(lic => {
            let statusBadge = "";
            if (lic.effective_status === "ACTIVE") {
                statusBadge = '<span class="badge-active">Ativa</span>';
            } else if (lic.effective_status === "BLOCKED") {
                statusBadge = '<span class="badge-blocked">Bloqueada</span>';
            } else if (lic.effective_status === "EXPIRED") {
                statusBadge = '<span class="badge-expired">Expirada</span>';
            }

            const expiresDisplay = lic.expires_at 
                ? escapeHtml(lic.expires_at.split("T")[0]) 
                : '<span style="color:#28a745; font-weight:bold;">Vitalícia</span>';

            const domainDisplay = lic.allowed_domain 
                ? `<code style="font-size:12px;">${escapeHtml(lic.allowed_domain)}</code>` 
                : '<span style="color:#777; font-size:12px;">Qualquer</span>';

            let lastSeenDisplay = '<span style="color:#999; font-size:12px;">Nunca comunicou</span>';
            if (lic.last_check_at) {
                const subDetails = [lic.last_ip, lic.last_version ? `v${lic.last_version}` : null, lic.last_hostname].filter(Boolean).join(" • ");
                lastSeenDisplay = `
                    <div style="font-weight: 500;">${escapeHtml(lic.last_check_relative)}</div>
                    <small style="color: #666; font-size: 11px;">${escapeHtml(subDetails)}</small>
                `;
            }

            const isBlocked = lic.status === "BLOCKED";
            const toggleBtnText = isBlocked ? "Desbloquear" : "Bloquear";
            const toggleBtnClass = isBlocked ? "btn-warning" : "btn-secondary";

            return `
                <tr class="${isBlocked ? 'row-inactive' : ''}">
                    <td>
                        <strong style="color: #007bff;">${escapeHtml(lic.client_name)}</strong>
                        ${lic.is_online ? '<span class="badge" style="background:#dcfce7; color:#15803d; border:1px solid #bbf7d0; font-size:10px; margin-left:6px;" title="Aplicação conectada em tempo real">● Ao Vivo</span>' : ''}
                        ${lic.notes ? `<div style="font-size: 11px; color: #666;">${escapeHtml(lic.notes)}</div>` : ''}
                    </td>
                    <td>
                        <span class="license-key-tag">
                            <span>${escapeHtml(lic.license_key)}</span>
                            <button type="button" class="btn-copy" onclick="copyLicenseKey('${escapeHtml(lic.license_key)}', this)" title="Copiar Chave">Copiar</button>
                        </span>
                    </td>
                    <td>${statusBadge}</td>
                    <td>${expiresDisplay}</td>
                    <td>${domainDisplay}</td>
                    <td>${lastSeenDisplay}</td>
                    <td style="text-align: center; font-weight: bold;">${lic.total_checks}</td>
                    <td class="actions-cell">
                        <button class="btn btn-info btn-sm" onclick="openLicenseLogsModal(${lic.id}, '${escapeHtml(lic.client_name)}', '${escapeHtml(lic.license_key)}')">Logs</button>
                        <button class="btn ${toggleBtnClass} btn-sm" onclick="toggleLicenseStatus(${lic.id})">${toggleBtnText}</button>
                        <button class="btn btn-primary btn-sm" onclick='openLicenseModal(${JSON.stringify(lic)})'>Editar</button>
                        <button class="btn btn-danger btn-sm" onclick="deleteLicense(${lic.id}, '${escapeHtml(lic.client_name)}')">Remover</button>
                    </td>
                </tr>
            `;
        }).join("");
    } catch (err) {
        console.error("Erro ao carregar licenças:", err);
    }
}

function openLicenseModal(lic = null) {
    const form = document.getElementById("license-form");
    form.reset();
    
    if (lic) {
        document.getElementById("license-modal-title").textContent = "Editar Licença";
        form.id.value = lic.id;
        form.client_name.value = lic.client_name;
        form.license_key.value = lic.license_key;
        form.status.value = lic.status;
        form.allowed_domain.value = lic.allowed_domain || "";
        form.notes.value = lic.notes || "";

        if (lic.expires_at) {
            form.expires_at.value = lic.expires_at.split("T")[0];
            document.getElementById("license-lifetime-checkbox").checked = false;
            form.expires_at.disabled = false;
        } else {
            form.expires_at.value = "";
            document.getElementById("license-lifetime-checkbox").checked = true;
            form.expires_at.disabled = true;
        }
    } else {
        document.getElementById("license-modal-title").textContent = "Nova Licença";
        form.id.value = "";
        form.status.value = "ACTIVE";
        document.getElementById("license-lifetime-checkbox").checked = true;
        form.expires_at.disabled = true;
        generateRandomKeyToInput();
    }
    openModal("license-modal");
}

function toggleLifetime(isLifetime) {
    const expiresInput = document.getElementById("license-expires-input");
    expiresInput.disabled = isLifetime;
    if (isLifetime) expiresInput.value = "";
}

async function generateRandomKeyToInput() {
    try {
        const res = await apiGet("/api/licenses/generate-key");
        if (res && res.license_key) {
            document.getElementById("license-key-input").value = res.license_key;
        }
    } catch (e) {
        console.error("Falha ao gerar chave:", e);
    }
}

async function copyLicenseKey(text, btn) {
    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
        } else {
            const input = document.createElement("input");
            input.value = text;
            document.body.appendChild(input);
            input.select();
            document.execCommand("copy");
            document.body.removeChild(input);
        }
        const oldText = btn.textContent;
        btn.textContent = "Copiado!";
        btn.style.backgroundColor = "#28a745";
        btn.style.color = "#fff";
        setTimeout(() => {
            btn.textContent = oldText;
            btn.style.backgroundColor = "";
            btn.style.color = "";
        }, 1500);
    } catch (err) {
        alert("Chave: " + text);
    }
}

async function toggleLicenseStatus(id) {
    try {
        await apiPost(`/api/licenses/${id}/toggle`);
        refreshLicenses();
        refreshSummary();
    } catch (err) {
        alert(err.message);
    }
}

async function deleteLicense(id, name) {
    if (!confirm(`Remover permanentemente a licença de "${name}"? Todo o histórico de conexões será apagado.`)) return;
    try {
        await apiDelete(`/api/licenses/${id}`);
        refreshLicenses();
        refreshSummary();
    } catch (err) {
        alert(err.message);
    }
}

async function openLicenseLogsModal(licenseId, clientName, licenseKey) {
    currentLicenseLogsId = licenseId;
    document.getElementById("license-logs-title").textContent = `Comunicações: ${clientName}`;
    document.getElementById("license-logs-subtitle").textContent = `Chave: ${licenseKey}`;
    openModal("license-logs-modal");
    await refreshLicenseLogs();
}

async function refreshLicenseLogs() {
    if (!currentLicenseLogsId) return;
    const tbody = document.getElementById("license-logs-tbody");
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #888; padding: 15px;">Atualizando comunicações...</td></tr>`;
    
    try {
        const data = await apiGet(`/api/licenses/${currentLicenseLogsId}/logs`);
        const logs = data.logs || [];
        document.getElementById("license-logs-count").textContent = `Total: ${logs.length} registro(s) recente(s)`;

        if (logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #888; padding: 20px;">Nenhuma comunicação registrada para esta licença até o momento.</td></tr>`;
            return;
        }

        tbody.innerHTML = logs.map(l => {
            let statusBadge = `<span class="badge-inactive">${escapeHtml(l.status_returned)}</span>`;
            if (l.status_returned === "ACTIVE") {
                statusBadge = `<span class="badge-active">ACTIVE (OK)</span>`;
            } else if (l.status_returned === "BLOCKED") {
                statusBadge = `<span class="badge-blocked">BLOQUEADA</span>`;
            } else if (l.status_returned === "EXPIRED") {
                statusBadge = `<span class="badge-expired">EXPIRADA</span>`;
            } else if (l.status_returned === "IP_NOT_ALLOWED") {
                statusBadge = `<span class="badge-blocked">IP/ASN NÃO PERMITIDO</span>`;
            } else if (l.status_returned === "DOMAIN_MISMATCH") {
                statusBadge = `<span class="badge-blocked">DOMÍNIO INVÁLIDO</span>`;
            } else if (l.status_returned === "ORIGIN_MISMATCH") {
                statusBadge = `<span class="badge-blocked">ORIGEM NÃO AUTORIZADA</span>`;
            }

            return `
                <tr>
                    <td style="white-space: nowrap;">
                        <div>${escapeHtml(l.timestamp)}</div>
                        <small style="color: #777;">(${escapeHtml(l.relative_time)})</small>
                    </td>
                    <td><code>${escapeHtml(l.ip)}</code></td>
                    <td>${escapeHtml(l.hostname)}</td>
                    <td>${escapeHtml(l.app_version)}</td>
                    <td>${statusBadge}</td>
                    <td>
                        <div>${escapeHtml(l.message)}</div>
                        ${l.details ? `<small style="color: #666; font-size: 11px;">${escapeHtml(l.details)}</small>` : ''}
                    </td>
                </tr>
            `;
        }).join("");
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #dc3545;">Erro ao obter histórico: ${escapeHtml(err.message)}</td></tr>`;
    }
}

async function clearCurrentLicenseLogs() {
    if (!currentLicenseLogsId) return;
    if (!confirm("Limpar todo o histórico de comunicações desta licença?")) return;
    try {
        await apiDelete(`/api/licenses/${currentLicenseLogsId}/logs`);
        await refreshLicenseLogs();
        refreshLicenses();
    } catch (err) {
        alert(err.message);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("license-form");
    if (!form) return;
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const id = form.id.value;
        const isLifetime = document.getElementById("license-lifetime-checkbox").checked;
        const body = {
            client_name: form.client_name.value.trim(),
            license_key: form.license_key.value.trim().toUpperCase(),
            status: form.status.value,
            expires_at: isLifetime ? null : form.expires_at.value,
            allowed_domain: form.allowed_domain.value.trim().toLowerCase(),
            notes: form.notes.value.trim(),
        };

        try {
            if (id) {
                await apiPut(`/api/licenses/${id}`, body);
            } else {
                await apiPost("/api/licenses", body);
            }
            closeModal("license-modal");
            refreshLicenses();
            refreshSummary();
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

    if (document.getElementById("stat-licenses-total")) {
        document.getElementById("stat-licenses-total").textContent = s.licenses_total ?? 0;
        document.getElementById("stat-licenses-active").textContent = s.licenses_active ?? 0;
        document.getElementById("stat-licenses-blocked").textContent = s.licenses_blocked ?? 0;
        document.getElementById("stat-licenses-checks").textContent = s.license_checks_today ?? 0;
    }
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
    await Promise.all([refreshLicenses(), refreshTargets(), refreshDevices(), refreshSummary()]);
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
