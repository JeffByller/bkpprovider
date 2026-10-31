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

// ---------- Global State ----------

let allDevices = [];
let quickActionsCatalog = [];
let telegramDestinations = [];
let currentSnmpDeviceId = null;
let currentLicenseLogsId = null;

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

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeAllModals();
});

document.addEventListener("mousedown", (e) => {
    if (e.target.classList.contains("modal-overlay")) {
        e.target.hidden = true;
    }
});

// ---------- Formatting & Badges ----------

function escapeHtml(str) {
    if (str == null) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function fmtLatency(v) { return v == null ? "-" : `${Number(v).toFixed(1)} ms`; }

function fmtBps(bps) {
    const n = Number(bps || 0);
    if (n <= 0) return "0 bps";
    if (n >= 1e9) return `${(n / 1e9).toFixed(2)} Gbps`;
    if (n >= 1e6) return `${(n / 1e6).toFixed(2)} Mbps`;
    if (n >= 1e3) return `${(n / 1e3).toFixed(1)} Kbps`;
    return `${n} bps`;
}

function fmtBytes(bytes) {
    const n = Number(bytes || 0);
    if (n <= 0) return "0 B";
    if (n >= 1073741824) return `${(n / 1073741824).toFixed(2)} GB`;
    if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
}

function statusBadge(d) {
    if (!d.active) return '<span class="badge badge-inactive">INATIVO</span>';
    if (!d.icmp_enabled) return '<span class="badge badge-inactive">SEM PING</span>';
    if (d.status === "UP") return '<span class="badge badge-up">● UP</span>';
    return '<span class="badge badge-down">▲ DOWN</span>';
}

function rosBadge(d) {
    const v = d.ros_version || "auto";
    const det = d.ros_version_detail ? ` (${escapeHtml(d.ros_version_detail)})` : "";
    if (v === "v7") return `<span class="badge-ros-v7">RouterOS v7${det}</span>`;
    if (v === "v6") return `<span class="badge-ros-v6">RouterOS v6${det}</span>`;
    return `<span class="badge-ros-auto">Auto${det}</span>`;
}

function modulesBadges(d) {
    const pills = [];
    pills.push(`<span class="mod-pill ${d.icmp_enabled ? 'mod-on' : 'mod-off'}">ICMP</span>`);
    pills.push(`<span class="mod-pill ${d.backup_enabled ? 'mod-on' : 'mod-off'}">BKP</span>`);
    pills.push(`<span class="mod-pill ${d.ssh_enabled ? 'mod-on' : 'mod-off'}">SSH</span>`);
    if (d.snmp_enabled) {
        const cls = d.snmp_status === "OK" ? "mod-snmp-ok" : "mod-snmp-err";
        const autoTag = d.snmp_auto_poll ? " 🔄" : "";
        const autoTitle = d.snmp_auto_poll
            ? `Coleta Automática ATIVA${d.snmp_auto_until ? ' até ' + d.snmp_auto_until : ' (contínua)'}`
            : (d.snmp_last_error || "SNMP configurado (coleta sob demanda)");
        pills.push(`<span class="mod-pill ${cls}" title="${escapeHtml(autoTitle)}">SNMP${autoTag}</span>`);
    } else {
        pills.push(`<span class="mod-pill mod-off">SNMP</span>`);
    }
    return pills.join("");
}

function renderHealthSummary(d) {
    const parts = [];
    if (d.cpu_load != null) parts.push(`CPU: <b>${d.cpu_load}%</b>`);
    if (d.memory_used_pct != null) parts.push(`Mem: <b>${Number(d.memory_used_pct).toFixed(0)}%</b>`);
    if (d.rx_bps > 0 || d.tx_bps > 0) {
        parts.push(`↓${fmtBps(d.rx_bps)} ↑${fmtBps(d.tx_bps)}`);
    }
    if (d.uptime_str) {
        parts.push(`<small style="color:#64748b; display:block;">Up: ${escapeHtml(d.uptime_str)}</small>`);
    }
    if (parts.length === 0) {
        return '<span class="sparkline-empty">Sem coleta</span>';
    }
    return parts.join(" • ");
}

// ---------- Sparkline (pure inline SVG) ----------

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

// ---------- Centralized Devices Inventory ----------

async function refreshDevices() {
    allDevices = await apiGet("/api/devices");
    renderDevicesTables();
    populateSshDeviceSelector();
}

function getFilteredDevices() {
    const q = (document.getElementById("device-search-input")?.value || "").trim().toLowerCase();
    const filter = document.getElementById("device-filter-select")?.value || "all";

    return allDevices.filter(d => {
        if (q) {
            const hay = `${d.name} ${d.ip} ${d.ros_version} ${d.ros_version_detail} ${d.board_name} ${d.notes}`.toLowerCase();
            if (!hay.includes(q)) return false;
        }
        if (filter === "v6" && d.ros_version !== "v6") return false;
        if (filter === "v7" && d.ros_version !== "v7") return false;
        if (filter === "up" && d.status !== "UP") return false;
        if (filter === "down" && d.status !== "DOWN") return false;
        if (filter === "backup" && !d.backup_enabled) return false;
        if (filter === "snmp" && !d.snmp_enabled) return false;
        return true;
    });
}

function renderDevicesTables() {
    // 1. Dashboard Overview Table
    const dashTbody = document.getElementById("dashboard-devices-tbody");
    if (dashTbody) {
        if (allDevices.length === 0) {
            dashTbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#888; padding:20px;">Nenhum dispositivo cadastrado.</td></tr>`;
        } else {
            dashTbody.innerHTML = allDevices.map(d => {
                const bkpStatus = d.backup_enabled
                    ? `<span class="badge ${d.last_backup_status === 'SUCCESS' ? 'badge-up' : (d.last_backup_status === 'PENDING' ? 'badge-inactive' : 'badge-down')}">${escapeHtml(d.last_backup || d.last_backup_status)}</span>`
                    : `<span class="sparkline-empty">Desabilitado</span>`;

                return `
                    <tr class="${d.active ? '' : 'row-inactive'}">
                        <td>
                            <strong>${escapeHtml(d.name)}</strong>
                            ${d.notes ? `<div style="font-size:11px; color:#64748b;">${escapeHtml(d.notes)}</div>` : ''}
                        </td>
                        <td>
                            <code>${escapeHtml(d.ip)}</code>${d.ssh_enabled || d.backup_enabled ? `<small style="color:#64748b;">:${d.ssh_port}</small>` : ''}
                        </td>
                        <td>
                            ${rosBadge(d)}
                            ${d.board_name ? `<div style="font-size:11px; color:#64748b; margin-top:2px;">${escapeHtml(d.board_name)}</div>` : ''}
                        </td>
                        <td>${statusBadge(d)}</td>
                        <td>${fmtLatency(d.latency_ms)} <small style="color:#64748b;">(méd: ${fmtLatency(d.avg_latency_ms)})</small></td>
                        <td>${renderHealthSummary(d)}</td>
                        <td>${bkpStatus}</td>
                        <td class="actions-cell">
                            ${d.ssh_enabled ? `<button class="btn btn-dark btn-sm" onclick="openSshTabForDevice(${d.id})">SSH / Comandos</button>` : ''}
                            <button class="btn btn-teal btn-sm" onclick="openSnmpModal(${d.id})">SNMP / Métricas</button>
                            ${d.backup_enabled ? `<button class="btn btn-info btn-sm" onclick="triggerBackup(${d.id}, this)">Backup</button>` : ''}
                            <button class="btn btn-primary btn-sm" onclick="openDeviceModalById(${d.id})">Editar</button>
                        </td>
                    </tr>
                `;
            }).join("");
        }
    }

    // 2. Central Devices Inventory Table (Tab 2)
    const centralTbody = document.getElementById("devices-central-tbody");
    if (centralTbody) {
        const filtered = getFilteredDevices();
        if (filtered.length === 0) {
            centralTbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#888; padding:20px;">Nenhum dispositivo corresponde ao filtro.</td></tr>`;
        } else {
            centralTbody.innerHTML = filtered.map(d => `
                <tr class="${d.active ? '' : 'row-inactive'}">
                    <td>
                        <strong>${escapeHtml(d.name)}</strong>
                        ${d.notes ? `<div style="font-size:11px; color:#64748b;">${escapeHtml(d.notes)}</div>` : ''}
                    </td>
                    <td>
                        <div><code>${escapeHtml(d.ip)}</code>:${d.ssh_port}</div>
                        ${d.ssh_username ? `<small style="color:#64748b;">usr: ${escapeHtml(d.ssh_username)}</small>` : '<small style="color:#94a3b8;">sem credencial SSH</small>'}
                    </td>
                    <td>
                        ${rosBadge(d)}
                        ${d.board_name ? `<div style="font-size:11px; color:#475569; margin-top:2px;">${escapeHtml(d.board_name)}</div>` : ''}
                    </td>
                    <td>${modulesBadges(d)}</td>
                    <td>
                        <div>${statusBadge(d)} <strong>${fmtLatency(d.latency_ms)}</strong></div>
                        <small style="color:#64748b;">Média: ${fmtLatency(d.avg_latency_ms)} | ${escapeHtml(d.last_check || '-')}</small>
                    </td>
                    <td>${renderSparkline(d.history)}</td>
                    <td>${renderHealthSummary(d)}</td>
                    <td class="actions-cell">
                        ${d.ssh_enabled ? `<button class="btn btn-dark btn-sm" onclick="openSshTabForDevice(${d.id})" title="Comandos e Ações Rápidas SSH">SSH</button>` : ''}
                        <button class="btn btn-teal btn-sm" onclick="openSnmpModal(${d.id})" title="Configurar SNMP e Ver Gráficos">SNMP</button>
                        ${d.backup_enabled ? `<button class="btn btn-info btn-sm" onclick="triggerBackup(${d.id}, this)">BKP</button>` : ''}
                        <button class="btn btn-primary btn-sm" onclick="openDeviceModalById(${d.id})">Editar</button>
                        <button class="btn ${d.active ? 'btn-warning' : 'btn-info'} btn-sm" onclick="toggleDevice(${d.id})">${d.active ? 'Pausar' : 'Ativar'}</button>
                        <button class="btn btn-danger btn-sm" onclick="deleteDevice(${d.id}, '${escapeHtml(d.name)}')">Excluir</button>
                    </td>
                </tr>
            `).join("");
        }
    }

    // 3. Backups Tab Table (Tab 4)
    const bkpTbody = document.getElementById("backups-devices-tbody");
    if (bkpTbody) {
        const bkpDevices = allDevices.filter(d => d.backup_enabled);
        if (bkpDevices.length === 0) {
            bkpTbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#888; padding:20px;">Nenhum dispositivo com módulo de Backup habilitado.</td></tr>`;
        } else {
            bkpTbody.innerHTML = bkpDevices.map(d => {
                const stClass = d.last_backup_status === "SUCCESS" ? "badge-up" : (d.last_backup_status === "PENDING" ? "badge-inactive" : "badge-down");
                return `
                    <tr>
                        <td><strong>${escapeHtml(d.name)}</strong></td>
                        <td><code>${escapeHtml(d.ip)}:${d.ssh_port}</code> (${escapeHtml(d.ssh_username)})</td>
                        <td>${rosBadge(d)}</td>
                        <td>${escapeHtml(d.last_backup || "-")}</td>
                        <td><span class="badge ${stClass}">${escapeHtml(d.last_backup_status)}</span></td>
                        <td>${renderFileOptions(d.id, d.files_detail || [])}</td>
                        <td class="actions-cell">
                            <button class="btn btn-primary btn-sm" onclick="triggerBackup(${d.id}, this)">Backup Agora</button>
                            <button class="btn btn-secondary btn-sm" onclick="openDeviceModalById(${d.id})">Configurar</button>
                        </td>
                    </tr>
                `;
            }).join("");
        }
    }
}

function renderFileOptions(deviceId, filesDetail) {
    if (!filesDetail || filesDetail.length === 0) {
        return '<span class="sparkline-empty">Nenhum arquivo</span>';
    }
    const options = filesDetail.map(f => `<option value="${escapeHtml(f.filename)}">${escapeHtml(f.filename)} (${f.size_kb} KB)</option>`).join("");
    return `
        <div style="display:flex; align-items:center; gap:4px; flex-wrap:wrap;">
            <select id="file-select-${deviceId}" style="max-width:250px;">${options}</select>
            <button type="button" class="btn btn-dark btn-sm" onclick="viewBackupFile(${deviceId})">Ver .rsc</button>
            <button type="button" class="btn btn-info btn-sm" onclick="downloadBackup(${deviceId})">Baixar</button>
        </div>
    `;
}

// ---------- Device Modal (Create / Edit) ----------

function toggleDeviceCredentialFields() {
    const form = document.getElementById("device-form");
    if (!form) return;
    const needSsh = form.backup_enabled.checked || form.ssh_enabled.checked;
    const sshSec = document.getElementById("device-ssh-section");
    const snmpSec = document.getElementById("device-snmp-section");
    if (sshSec) sshSec.style.opacity = needSsh ? "1" : "0.75";
    if (snmpSec) snmpSec.style.opacity = form.snmp_enabled.checked ? "1" : "0.75";
}

function openDeviceModalById(deviceId) {
    const dev = allDevices.find(d => d.id === deviceId);
    openDeviceModal(dev || null);
}

function openDeviceModal(device = null) {
    const form = document.getElementById("device-form");
    form.reset();
    form.id.value = device ? device.id : "";
    const hint = document.getElementById("device-password-hint");

    if (device) {
        document.getElementById("device-modal-title").textContent = `Editar Dispositivo: ${device.name}`;
        form.name.value = device.name;
        form.ip.value = device.ip;
        form.device_type.value = device.device_type || "mikrotik";
        form.ros_version.value = device.ros_version || "auto";
        form.ssh_port.value = device.ssh_port || 2250;
        form.ssh_username.value = device.ssh_username || "";
        form.ssh_password.value = "";
        form.icmp_enabled.checked = Boolean(device.icmp_enabled);
        form.backup_enabled.checked = Boolean(device.backup_enabled);
        form.ssh_enabled.checked = Boolean(device.ssh_enabled);
        form.snmp_enabled.checked = Boolean(device.snmp_enabled);
        form.snmp_community.value = device.snmp_community || "@BKP2712";
        form.snmp_port.value = device.snmp_port || 161;
        form.telegram_destination_id.value = device.telegram_destination_id || "";
        if (form.notes) form.notes.value = device.notes || "";
        hint.hidden = !device.has_password;
    } else {
        document.getElementById("device-modal-title").textContent = "Cadastrar Novo Dispositivo";
        form.device_type.value = "mikrotik";
        form.ros_version.value = "auto";
        form.ssh_port.value = 2250;
        form.ssh_username.value = "gerabackup";
        form.ssh_password.value = "gerabackup";
        form.icmp_enabled.checked = true;
        form.backup_enabled.checked = true;
        form.ssh_enabled.checked = true;
        form.snmp_enabled.checked = false;
        form.snmp_community.value = "@BKP2712";
        form.snmp_port.value = 161;
        form.telegram_destination_id.value = "";
        if (form.notes) form.notes.value = "";
        hint.hidden = true;
    }
    toggleDeviceCredentialFields();
    openModal("device-modal");
}

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("device-form");
    if (!form) return;
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const id = form.id.value;
        const body = {
            name: form.name.value.trim(),
            ip: form.ip.value.trim(),
            device_type: form.device_type.value,
            ros_version: form.ros_version.value,
            ssh_port: parseInt(form.ssh_port.value, 10) || 2250,
            ssh_username: form.ssh_username.value.trim(),
            ssh_password: form.ssh_password.value,
            icmp_enabled: form.icmp_enabled.checked,
            backup_enabled: form.backup_enabled.checked,
            ssh_enabled: form.ssh_enabled.checked,
            snmp_enabled: form.snmp_enabled.checked,
            snmp_community: form.snmp_community.value.trim() || "@BKP2712",
            snmp_port: parseInt(form.snmp_port.value, 10) || 161,
            telegram_destination_id: form.telegram_destination_id.value ? parseInt(form.telegram_destination_id.value, 10) : null,
        };
        if (form.notes) {
            body.notes = form.notes.value.trim();
        }
        try {
            if (id) await apiPut(`/api/devices/${id}`, body);
            else await apiPost("/api/devices", body);
            closeModal("device-modal");
            await refreshAll();
        } catch (err) {
            alert(err.message);
        }
    });
});

async function toggleDevice(id) {
    await apiPost(`/api/devices/${id}/toggle`);
    await refreshAll();
}

async function deleteDevice(id, name) {
    if (!confirm(`Remover o dispositivo "${name}" do cadastro centralizado?`)) return;
    await apiDelete(`/api/devices/${id}`);
    await refreshAll();
}

// ---------- Backups & Backup Viewer ----------

async function triggerBackup(id, btn) {
    const origText = btn ? btn.textContent : "";
    if (btn) {
        btn.disabled = true;
        btn.textContent = "Executando...";
    }
    try {
        const result = await apiPost(`/api/devices/${id}/backup-now`);
        alert(result.ok ? `✅ ${result.message}` : `❌ Falha no backup: ${result.message}`);
    } catch (err) {
        alert(err.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = origText;
        }
        await Promise.all([refreshDevices(), refreshBackupHistory(), refreshSummary()]);
    }
}

async function triggerBackupAll(btn) {
    if (!confirm("Executar backup agora em todos os equipamentos habilitados?")) return;
    const orig = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Executando backups em lote...";
    try {
        const res = await apiPost("/api/devices/backup-all");
        alert(res.message || "Rotina finalizada!");
    } catch (e) {
        alert(e.message);
    } finally {
        btn.disabled = false;
        btn.textContent = orig;
        await Promise.all([refreshDevices(), refreshBackupHistory(), refreshSummary()]);
    }
}

async function viewBackupFile(deviceId) {
    const select = document.getElementById(`file-select-${deviceId}`);
    if (!select || !select.value) return;
    const filename = select.value;
    const password = prompt("Digite a senha administrativa para visualizar o script de backup:");
    if (!password) return;
    try {
        const res = await apiGet(`/api/devices/backups/view?filename=${encodeURIComponent(filename)}&password=${encodeURIComponent(password)}`);
        document.getElementById("backup-view-title").textContent = `Arquivo: ${res.filename}`;
        document.getElementById("backup-view-subtitle").textContent = `Tamanho: ${(res.size_bytes / 1024).toFixed(1)} KB`;
        document.getElementById("backup-view-content").textContent = res.content;
        openModal("backup-view-modal");
    } catch (e) {
        alert(e.message);
    }
}

function copyBackupViewerContent() {
    const text = document.getElementById("backup-view-content").textContent;
    navigator.clipboard?.writeText(text);
    alert("Conteúdo copiado para a área de transferência!");
}

function downloadBackup(deviceId) {
    const select = document.getElementById(`file-select-${deviceId}`);
    const filename = select.value;
    const password = prompt("Digite a senha administrativa para autorizar o download do backup:");
    if (password) {
        window.location.href = `/mikrotik/download?filename=${encodeURIComponent(filename)}&password=${encodeURIComponent(password)}`;
    }
}

let backupHistoryCurrentPage = 1;
const BACKUP_HISTORY_PAGE_SIZE = 25;

async function refreshBackupHistory(page) {
    if (typeof page === "number" && page >= 1) {
        backupHistoryCurrentPage = page;
    }
    const tbody = document.getElementById("backup-history-tbody");
    const pager = document.getElementById("backup-history-pagination");
    if (!tbody) return;
    try {
        const data = await apiGet(`/api/devices/backups/history?page=${backupHistoryCurrentPage}&page_size=${BACKUP_HISTORY_PAGE_SIZE}`);
        const rows = Array.isArray(data) ? data : (data.items || []);
        const total = Array.isArray(data) ? rows.length : (data.total || 0);
        const curPage = Array.isArray(data) ? 1 : (data.page || 1);
        const totalPages = Array.isArray(data) ? 1 : (data.total_pages || 1);
        backupHistoryCurrentPage = curPage;

        if (rows.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#888; padding:16px;">Nenhum registro de backup encontrado.</td></tr>`;
            if (pager) pager.innerHTML = `<span>0 registros</span>`;
            return;
        }
        tbody.innerHTML = rows.map(r => `
            <tr>
                <td style="white-space:nowrap;">${escapeHtml(r.created_at)}</td>
                <td><strong>${escapeHtml(r.device_name)}</strong> <small style="color:#64748b;">(${escapeHtml(r.device_ip)})</small></td>
                <td><code>${escapeHtml(r.ros_version || "-")}</code></td>
                <td><span class="badge badge-inactive">${escapeHtml(r.trigger_type)}</span></td>
                <td><span class="badge ${r.status === 'SUCCESS' ? 'badge-up' : 'badge-down'}">${escapeHtml(r.status)}</span></td>
                <td>${r.size_bytes ? `${(r.size_bytes / 1024).toFixed(1)} KB` : "-"}</td>
                <td>${r.duration_ms ? `${r.duration_ms} ms` : "-"}</td>
                <td>
                    ${r.filename ? `<code>${escapeHtml(r.filename)}</code> — ` : ""}
                    <small style="color:#475569;">${escapeHtml(r.message)}</small>
                </td>
            </tr>
        `).join("");

        if (pager) {
            const startIdx = (curPage - 1) * BACKUP_HISTORY_PAGE_SIZE + 1;
            const endIdx = Math.min(startIdx + rows.length - 1, total);
            let pageButtons = "";
            const pagesToShow = [];
            if (totalPages <= 10) {
                for (let p = 1; p <= totalPages; p++) pagesToShow.push(p);
            } else {
                pagesToShow.push(1);
                const startP = Math.max(2, curPage - 2);
                const endP = Math.min(totalPages - 1, curPage + 2);
                if (startP > 2) pagesToShow.push("...");
                for (let p = startP; p <= endP; p++) pagesToShow.push(p);
                if (endP < totalPages - 1) pagesToShow.push("...");
                pagesToShow.push(totalPages);
            }
            for (const p of pagesToShow) {
                if (p === "...") {
                    pageButtons += `<span style="padding:4px 6px; color:#64748b;">...</span>`;
                } else {
                    const activeStyle = p === curPage
                        ? "background:#2563eb; color:#fff; border-color:#2563eb;"
                        : "background:#f8fafc; color:#334155; border-color:#cbd5e1;";
                    pageButtons += `<button type="button" class="btn btn-sm" style="padding:4px 10px; border:1px solid; ${activeStyle}" onclick="refreshBackupHistory(${p})">${p}</button>`;
                }
            }
            pager.innerHTML = `
                <span>Exibindo <b>${startIdx}–${endIdx}</b> de <b>${total}</b> registros</span>
                <div style="display:flex; gap:4px; align-items:center;">
                    <button type="button" class="btn btn-sm" style="padding:4px 10px; background:#f8fafc; color:#334155; border:1px solid #cbd5e1;" ${curPage <= 1 ? "disabled" : ""} onclick="refreshBackupHistory(${curPage - 1})">« Anterior</button>
                    ${pageButtons}
                    <button type="button" class="btn btn-sm" style="padding:4px 10px; background:#f8fafc; color:#334155; border:1px solid #cbd5e1;" ${curPage >= totalPages ? "disabled" : ""} onclick="refreshBackupHistory(${curPage + 1})">Próxima »</button>
                </div>
            `;
        }
    } catch (e) {
        console.error(e);
    }
}

// ---------- Remote SSH Access & Quick Actions ----------

async function loadQuickActionsCatalog() {
    try {
        quickActionsCatalog = await apiGet("/api/devices/ssh/actions");
        const grid = document.getElementById("quick-actions-grid");
        if (!grid) return;
        grid.innerHTML = quickActionsCatalog.map(a => `
            <button type="button" class="quick-action-btn" onclick="runQuickAction('${escapeHtml(a.key)}', ${Boolean(a.requires_param)}, '${escapeHtml(a.param_label || '')}')">
                <strong>⚡ ${escapeHtml(a.label)}</strong>
                <small>${escapeHtml(a.description)}</small>
            </button>
        `).join("");
    } catch (e) {
        console.error("Erro ao carregar catálogo SSH:", e);
    }
}

function populateSshDeviceSelector() {
    const sel = document.getElementById("ssh-device-select");
    if (!sel) return;
    const currentVal = sel.value;
    const sshDevs = allDevices.filter(d => d.ssh_enabled);
    if (sshDevs.length === 0) {
        sel.innerHTML = `<option value="">Nenhum dispositivo com SSH habilitado</option>`;
        return;
    }
    sel.innerHTML = sshDevs.map(d => {
        const ver = d.ros_version_detail ? `RouterOS ${d.ros_version_detail}` : d.ros_version.toUpperCase();
        return `<option value="${d.id}">${escapeHtml(d.name)} (${escapeHtml(d.ip)}:${d.ssh_port}) — [${escapeHtml(ver)}]</option>`;
    }).join("");
    if (currentVal && sshDevs.some(d => String(d.id) === String(currentVal))) {
        sel.value = currentVal;
    }
    onSshDeviceChange();
}

let lastAnalyzedFailoverDeviceId = null;

function onSshDeviceChange() {
    const sel = document.getElementById("ssh-device-select");
    const banner = document.getElementById("ssh-device-banner");
    if (!sel || !banner) return;
    const dev = allDevices.find(d => String(d.id) === String(sel.value));
    if (!dev) {
        banner.innerHTML = "Selecione um equipamento com SSH habilitado.";
        return;
    }
    const destObj = telegramDestinations.find(t => String(t.id) === String(dev.telegram_destination_id));
    const tgLabel = destObj ? `Destino Telegram: <b>${escapeHtml(destObj.name)}</b>` : `Destino Telegram: <b>Padrão do Sistema</b>`;
    banner.innerHTML = `
        <strong>Equipamento conectado ao console:</strong> ${escapeHtml(dev.name)}
        (<code>${escapeHtml(dev.ip)}:${dev.ssh_port}</code>, usuário: <code>${escapeHtml(dev.ssh_username)}</code>)
        • ${rosBadge(dev)}
        ${dev.board_name ? `• Modelo: <b>${escapeHtml(dev.board_name)}</b>` : ""}
        ${dev.uptime_str ? `• Uptime: <b>${escapeHtml(dev.uptime_str)}</b>` : ""}
        • ${tgLabel}
    `;

    if (String(lastAnalyzedFailoverDeviceId) !== String(dev.id)) {
        const badge = document.getElementById("failover-status-badge");
        const sumEl = document.getElementById("failover-analysis-summary");
        const fbEl = document.getElementById("fo-feedback-msg");
        if (badge) {
            badge.hidden = true;
            badge.className = "badge badge-inactive";
            badge.textContent = "";
        }
        if (sumEl) {
            sumEl.innerHTML = `Equipamento selecionado: <b>${escapeHtml(dev.name)}</b> (${rosBadge(dev)}). Clique em <b>"🔍 1. Analisar"</b> para identificar automaticamente os links e rotas.`;
        }
        if (fbEl) {
            fbEl.style.color = "#64748b";
            fbEl.textContent = "";
        }
    }
}

function toggleFailoverPanel() {
    const body = document.getElementById("failover-assistant-body");
    const chev = document.getElementById("failover-chevron");
    if (!body) return;
    body.hidden = !body.hidden;
    if (chev) {
        chev.textContent = body.hidden ? "▼ Expandir" : "▲ Ocultar";
    }
}

async function analyzeSelectedDeviceFailover() {
    const sel = document.getElementById("ssh-device-select");
    if (!sel || !sel.value) {
        alert("Selecione um dispositivo com SSH habilitado.");
        return;
    }
    const devId = sel.value;
    const btn = document.getElementById("btn-failover-analyze");
    const sumEl = document.getElementById("failover-analysis-summary");
    const badge = document.getElementById("failover-status-badge");
    const outPre = document.getElementById("terminal-output");
    const titleEl = document.getElementById("terminal-title");
    const metaEl = document.getElementById("terminal-meta");
    const body = document.getElementById("failover-assistant-body");
    const chev = document.getElementById("failover-chevron");
    if (body) body.hidden = false;
    if (chev) chev.textContent = "▲ Ocultar";

    if (btn) {
        btn.disabled = true;
        btn.textContent = "⏳ Analisando...";
    }
    if (sumEl) {
        sumEl.innerHTML = "⏳ Conectando via SSH para inspecionar interfaces WAN, Rotas e Netwatch...";
    }
    outPre.textContent = "⏳ Executando análise de Failover no equipamento via SSH...";

    try {
        const res = await apiPost(`/api/devices/${devId}/failover/analyze`);
        if (!res.ok) {
            const errMsg = res.error || "Falha ao analisar equipamento.";
            if (sumEl) sumEl.innerHTML = `<span style="color:#dc2626; font-weight:bold;">❌ ${escapeHtml(errMsg)}</span>`;
            outPre.textContent = `❌ ${errMsg}`;
            return;
        }

        lastAnalyzedFailoverDeviceId = devId;
        const a = res.analysis;
        const sug = a.suggested || {};

        // Populate datalist with detected WAN candidates
        const dl = document.getElementById("failover-wan-datalist");
        if (dl) {
            dl.innerHTML = (a.wan_candidates || []).map(c =>
                `<option value="${escapeHtml(c.gateway)}">${escapeHtml(c.label)}</option>`
            ).join("");
        }

        // Pre-fill Step 2 form fields
        const gw1Input = document.getElementById("fo-link1-gw");
        const gw2Input = document.getElementById("fo-link2-gw");
        const h1Input = document.getElementById("fo-link1-host");
        const h2Input = document.getElementById("fo-link2-host");
        const d1Input = document.getElementById("fo-link1-dist");
        const d2Input = document.getElementById("fo-link2-dist");
        const intInput = document.getElementById("fo-interval");

        if (gw1Input) gw1Input.value = sug.link1_gateway || "";
        if (gw2Input) gw2Input.value = sug.link2_gateway || "";
        if (h1Input) h1Input.value = sug.link1_host || "198.41.0.4";
        if (h2Input) h2Input.value = sug.link2_host || "199.9.14.201";
        if (d1Input) d1Input.value = sug.link1_distance || 1;
        if (d2Input) d2Input.value = sug.link2_distance || 2;
        if (intInput) intInput.value = sug.interval || "10s";

        // Update status badge
        if (badge) {
            badge.hidden = false;
            if (a.is_configured) {
                const anyDown = (a.netwatch || []).some(n => n.status === "down");
                const allDisabled = (a.netwatch || []).length > 0 && (a.netwatch || []).every(n => n.disabled);
                if (allDisabled) {
                    badge.className = "badge badge-inactive";
                    badge.textContent = "⚪ NETWATCH PAUSADO";
                } else if (anyDown) {
                    badge.className = "badge badge-down";
                    badge.textContent = "⚠️ FAILOVER ATIVO (LINK DOWN)";
                } else {
                    badge.className = "badge badge-up";
                    badge.textContent = "🟢 FAILOVER ATIVO & OK";
                }
            } else {
                badge.className = "badge badge-inactive";
                badge.textContent = "⚙️ PRONTO PARA CONFIGURAR";
            }
        }

        // Render visual summary in #failover-analysis-summary
        const wanPills = (a.wan_candidates || [])
            .filter(c => c.type !== "ethernet")
            .slice(0, 6)
            .map(c => `<span style="display:inline-block; background:#f1f5f9; border:1px solid #cbd5e1; border-radius:4px; padding:2px 7px; margin:2px 4px 2px 0; font-family:monospace; font-size:11px;"><b>${escapeHtml(c.gateway)}</b> <small style="color:#64748b;">(${escapeHtml(c.type.toUpperCase())})</small></span>`)
            .join("") || `<span style="color:#94a3b8;">Nenhum PPPoE/DHCP detectado</span>`;

        const nwPills = (a.netwatch || []).map(nw => {
            const st = (nw.status || "").toUpperCase();
            const cls = nw.disabled ? "badge-inactive" : (st === "UP" ? "badge-up" : (st === "DOWN" ? "badge-down" : "badge-inactive"));
            const tgIcon = nw.has_telegram ? " 🔔Telegram" : "";
            return `<span class="badge ${cls}" style="margin-right:6px;">${escapeHtml(nw.comment || nw.host)}: ${escapeHtml(st)} (${escapeHtml(nw.host)})${tgIcon}</span>`;
        }).join("") || `<span style="color:#64748b;">Nenhuma regra Netwatch ativa</span>`;

        if (sumEl) {
            sumEl.innerHTML = `
                <div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:6px; margin-bottom:6px;">
                    <div>
                        <b>Identidade:</b> <code>${escapeHtml(a.identity || "-")}</code> •
                        <b>Sistema:</b> <code>RouterOS ${escapeHtml(a.ros_version_detail)} (${escapeHtml(a.ros_version.toUpperCase())})</code> •
                        <b>Modelo:</b> ${escapeHtml(a.board_name || "-")}
                    </div>
                    <small style="color:#0f766e; font-weight:bold;">✅ Análise concluída (${res.duration_ms} ms)</small>
                </div>
                <div style="margin-bottom:4px;"><b>Links Detectados:</b> ${wanPills}</div>
                <div><b>Netwatch Atual:</b> ${nwPills}</div>
            `;
        }

        const fbEl = document.getElementById("fo-feedback-msg");
        if (fbEl) {
            fbEl.style.color = "#0f766e";
            fbEl.textContent = `RouterOS ${a.ros_version.toUpperCase()} detectado`;
        }

        titleEl.textContent = `Análise de Failover — ${a.identity || ""}`;
        metaEl.textContent = `RouterOS ${a.ros_version_detail} • ${res.duration_ms} ms • ${res.timestamp}`;
        outPre.textContent = a.terminal_report || "";

        await Promise.all([refreshDevices(), refreshCommandLogs()]);
    } catch (e) {
        if (sumEl) sumEl.innerHTML = `<span style="color:#dc2626; font-weight:bold;">❌ Erro: ${escapeHtml(e.message)}</span>`;
        outPre.textContent = `❌ Erro ao analisar failover: ${e.message}`;
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = "🔍 1. Analisar";
        }
    }
}

async function configureSelectedDeviceFailover() {
    const sel = document.getElementById("ssh-device-select");
    if (!sel || !sel.value) {
        alert("Selecione um dispositivo com SSH habilitado.");
        return;
    }
    const devId = sel.value;
    const dev = allDevices.find(d => String(d.id) === String(devId));
    const link1Gw = (document.getElementById("fo-link1-gw")?.value || "").trim();
    const link2Gw = (document.getElementById("fo-link2-gw")?.value || "").trim();
    const link1Host = (document.getElementById("fo-link1-host")?.value || "198.41.0.4").trim();
    const link2Host = (document.getElementById("fo-link2-host")?.value || "199.9.14.201").trim();
    const link1Dist = parseInt(document.getElementById("fo-link1-dist")?.value || "1", 10) || 1;
    const link2Dist = parseInt(document.getElementById("fo-link2-dist")?.value || "2", 10) || 2;
    const interval = (document.getElementById("fo-interval")?.value || "10s").trim();

    if (!link1Gw) {
        alert("Informe o Gateway / Interface do Link 1 (Principal), ou clique em '1. Analisar' primeiro.");
        return;
    }

    const confirmMsg = `Confirmar configuração de Failover e Netwatch em "${dev ? dev.name : devId}"?\n\n• Link 1 (PRINCIPAL): ${link1Gw} ➔ Ping ${link1Host} (dist=${link1Dist})\n• Link 2 (BACKUP): ${link2Gw || '(nenhum)'} ➔ Ping ${link2Host} (dist=${link2Dist})\n• Intervalo Netwatch: ${interval}\n• Alerta no Telegram: Padrão Ativo`;

    if (!confirm(confirmMsg)) return;

    const btn = document.getElementById("btn-failover-configure");
    const fbEl = document.getElementById("fo-feedback-msg");
    const outPre = document.getElementById("terminal-output");
    const titleEl = document.getElementById("terminal-title");
    const metaEl = document.getElementById("terminal-meta");

    if (btn) {
        btn.disabled = true;
        btn.textContent = "⏳ Configurando...";
    }
    if (fbEl) {
        fbEl.style.color = "#0369a1";
        fbEl.textContent = "Aplicando /ip route e /tool netwatch...";
    }
    outPre.textContent = "⏳ Aplicando configuração de Failover (/ip route e /tool netwatch) via SSH...";

    try {
        const res = await apiPost(`/api/devices/${devId}/failover/configure`, {
            link1_gateway: link1Gw,
            link2_gateway: link2Gw,
            link1_host: link1Host,
            link2_host: link2Host,
            link1_distance: link1Dist,
            link2_distance: link2Dist,
            interval: interval,
        });

        if (!res.ok) {
            const errMsg = res.error || "Falha ao configurar failover.";
            if (fbEl) {
                fbEl.style.color = "#dc2626";
                fbEl.textContent = `❌ ${errMsg}`;
            }
            outPre.textContent = `❌ ${errMsg}\n\n${res.output || ""}`;
            return;
        }

        if (fbEl) {
            fbEl.style.color = "#15803d";
            fbEl.textContent = `✅ ${res.message} (${res.duration_ms} ms)`;
        }
        titleEl.textContent = `Configuração de Failover Aplicada — ${dev ? dev.name : ""}`;
        metaEl.textContent = `${res.duration_ms} ms • ${res.timestamp}`;
        outPre.textContent = res.output || res.message;

        const badge = document.getElementById("failover-status-badge");
        if (badge) {
            badge.hidden = false;
            badge.className = "badge badge-up";
            badge.textContent = "🟢 FAILOVER CONFIGURADO & ATIVO";
        }

        await Promise.all([refreshDevices(), refreshCommandLogs()]);
    } catch (e) {
        if (fbEl) {
            fbEl.style.color = "#dc2626";
            fbEl.textContent = `❌ Erro: ${e.message}`;
        }
        outPre.textContent = `❌ Erro ao configurar failover: ${e.message}`;
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = "⚡ 2. Configurar";
        }
    }
}

async function toggleSelectedDeviceNetwatch(enable) {
    const sel = document.getElementById("ssh-device-select");
    if (!sel || !sel.value) {
        alert("Selecione um dispositivo com SSH habilitado.");
        return;
    }
    const devId = sel.value;
    const outPre = document.getElementById("terminal-output");
    outPre.textContent = `⏳ ${enable ? "Ativando" : "Pausando"} regras de Netwatch de Failover via SSH...`;
    try {
        const res = await apiPost(`/api/devices/${devId}/failover/toggle-netwatch`, { enable: Boolean(enable) });
        if (!res.ok) {
            outPre.textContent = `❌ ${res.error || "Erro ao alternar Netwatch"}`;
            return;
        }
        outPre.textContent = `✅ ${res.message}\n\n${res.output || ""}`;
        await analyzeSelectedDeviceFailover();
    } catch (e) {
        outPre.textContent = `❌ Erro: ${e.message}`;
    }
}

async function testSelectedDeviceFailoverTelegram() {
    const sel = document.getElementById("ssh-device-select");
    if (!sel || !sel.value) {
        alert("Selecione um dispositivo primeiro.");
        return;
    }
    try {
        const res = await apiPost(`/api/devices/${sel.value}/failover/test-telegram`);
        alert(res.ok ? `✅ ${res.message}` : `❌ Falha ao enviar teste.`);
    } catch (e) {
        alert(`❌ Erro: ${e.message}`);
    }
}

function openSshTabForDevice(deviceId) {
    switchTab("tab-ssh");
    const sel = document.getElementById("ssh-device-select");
    if (sel) {
        sel.value = String(deviceId);
        onSshDeviceChange();
    }
}

async function probeSelectedSshDevice() {
    const sel = document.getElementById("ssh-device-select");
    if (!sel || !sel.value) return;
    const outPre = document.getElementById("terminal-output");
    outPre.textContent = "Conectando via SSH e identificando versão do RouterOS e hardware...";
    try {
        const res = await apiPost(`/api/devices/${sel.value}/probe-ssh`);
        await refreshDevices();
        outPre.textContent = res.ok
            ? `✅ ${res.message}\nVersão detectada: ${res.info?.ros_version_detail || res.info?.ros_version}\nHardware: ${res.info?.board_name || '-'} (${res.info?.architecture || '-'})\nUptime: ${res.info?.uptime_str || '-'}\nChave SSH: ${res.info?.ssh_host_key || '-'}`
            : `❌ Falha na conexão SSH: ${res.message}`;
    } catch (e) {
        outPre.textContent = `❌ Erro: ${e.message}`;
    }
}

async function runQuickAction(actionKey, requiresParam, paramLabel) {
    const sel = document.getElementById("ssh-device-select");
    if (!sel || !sel.value) {
        alert("Selecione um dispositivo com SSH habilitado.");
        return;
    }
    let targetParam = "";
    if (requiresParam) {
        targetParam = prompt(paramLabel || "Informe o IP ou Host de destino:", "8.8.8.8");
        if (!targetParam) return;
    }
    await executeSshOnDevice(sel.value, actionKey, targetParam, "");
}

async function runCustomSshCommand() {
    const sel = document.getElementById("ssh-device-select");
    const input = document.getElementById("ssh-custom-cmd-input");
    if (!sel || !sel.value) {
        alert("Selecione um dispositivo com SSH habilitado.");
        return;
    }
    const cmd = (input.value || "").trim();
    if (!cmd) {
        alert("Digite um comando RouterOS para executar.");
        return;
    }
    await executeSshOnDevice(sel.value, "custom", "", cmd);
}

async function executeSshOnDevice(deviceId, actionKey, targetParam, customCmd) {
    const outPre = document.getElementById("terminal-output");
    const titleEl = document.getElementById("terminal-title");
    const metaEl = document.getElementById("terminal-meta");
    outPre.textContent = "⏳ Executando comando via SSH no equipamento...";
    metaEl.textContent = "";

    try {
        const res = await apiPost(`/api/devices/${deviceId}/ssh/execute`, {
            action_key: actionKey,
            target_param: targetParam,
            custom_cmd: customCmd,
        });
        if (!res.ok && res.error) {
            outPre.textContent = `❌ ${res.error}`;
            return;
        }
        titleEl.textContent = `Comando: ${res.command || actionKey}`;
        metaEl.textContent = `RouterOS ${res.ros_version || '-'} • ${res.duration_ms || 0} ms • ${res.timestamp || ''}`;
        outPre.textContent = res.output || "(Sem saída)";
        await Promise.all([refreshDevices(), refreshCommandLogs()]);
    } catch (e) {
        outPre.textContent = `❌ Erro ao executar comando: ${e.message}`;
    }
}

function copyTerminalOutput() {
    const text = document.getElementById("terminal-output").textContent;
    navigator.clipboard?.writeText(text);
}

function clearTerminalOutput() {
    document.getElementById("terminal-output").textContent = "Terminal limpo.";
    document.getElementById("terminal-meta").textContent = "";
}

let commandLogsCurrentPage = 1;
const COMMAND_LOGS_PAGE_SIZE = 25;

async function refreshCommandLogs(page) {
    if (typeof page === "number" && page >= 1) {
        commandLogsCurrentPage = page;
    }
    const tbody = document.getElementById("command-logs-tbody");
    const pager = document.getElementById("command-logs-pagination");
    if (!tbody) return;
    try {
        const data = await apiGet(`/api/devices/ssh/logs?page=${commandLogsCurrentPage}&page_size=${COMMAND_LOGS_PAGE_SIZE}`);
        const rows = Array.isArray(data) ? data : (data.items || []);
        const total = Array.isArray(data) ? rows.length : (data.total || 0);
        const curPage = Array.isArray(data) ? 1 : (data.page || 1);
        const totalPages = Array.isArray(data) ? 1 : (data.total_pages || 1);
        commandLogsCurrentPage = curPage;

        if (rows.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#888; padding:16px;">Nenhuma operação remota registrada ainda.</td></tr>`;
            if (pager) pager.innerHTML = `<span>0 registros</span><span>Retenção automática: máx. 200 registros</span>`;
            return;
        }
        tbody.innerHTML = rows.map(r => `
            <tr>
                <td style="white-space:nowrap;">${escapeHtml(r.created_at)}</td>
                <td><strong>${escapeHtml(r.device_name)}</strong> <small style="color:#64748b;">(${escapeHtml(r.device_ip)})</small></td>
                <td><code>${escapeHtml(r.command_executed)}</code></td>
                <td><span class="badge ${r.status === 'SUCCESS' ? 'badge-up' : 'badge-down'}">${escapeHtml(r.status)}</span></td>
                <td>${r.duration_ms} ms</td>
                <td><code>${escapeHtml(r.client_ip || "-")}</code></td>
                <td><small style="color:#334155; font-family:monospace;">${escapeHtml((r.output_preview || "").slice(0, 140))}${(r.output_preview || "").length > 140 ? "..." : ""}</small></td>
            </tr>
        `).join("");

        if (pager) {
            const startIdx = (curPage - 1) * COMMAND_LOGS_PAGE_SIZE + 1;
            const endIdx = Math.min(startIdx + rows.length - 1, total);
            let pageButtons = "";
            for (let p = 1; p <= totalPages; p++) {
                const activeStyle = p === curPage
                    ? "background:#2563eb; color:#fff; border-color:#2563eb;"
                    : "background:#f8fafc; color:#334155; border-color:#cbd5e1;";
                pageButtons += `<button type="button" class="btn btn-sm" style="padding:4px 10px; border:1px solid; ${activeStyle}" onclick="refreshCommandLogs(${p})">${p}</button>`;
            }
            pager.innerHTML = `
                <span>Exibindo <b>${startIdx}–${endIdx}</b> de <b>${total}</b> registros <small style="color:#64748b;">(limite automático: 200)</small></span>
                <div style="display:flex; gap:4px; align-items:center;">
                    <button type="button" class="btn btn-sm" style="padding:4px 10px; background:#f8fafc; color:#334155; border:1px solid #cbd5e1;" ${curPage <= 1 ? "disabled" : ""} onclick="refreshCommandLogs(${curPage - 1})">« Anterior</button>
                    ${pageButtons}
                    <button type="button" class="btn btn-sm" style="padding:4px 10px; background:#f8fafc; color:#334155; border:1px solid #cbd5e1;" ${curPage >= totalPages ? "disabled" : ""} onclick="refreshCommandLogs(${curPage + 1})">Próxima »</button>
                </div>
            `;
        }
    } catch (e) {
        console.error(e);
    }
}

// ---------- SNMP Automated Provisioning & Metrics Charts ----------

let snmpModalLiveTimer = null;
let lastLoadedMetricsData = null;

function closeSnmpModal() {
    if (snmpModalLiveTimer) {
        clearInterval(snmpModalLiveTimer);
        snmpModalLiveTimer = null;
    }
    closeModal("snmp-modal");
}

function toggleSnmpModalLiveRefresh() {
    const chk = document.getElementById("snmp-live-refresh-chk");
    if (snmpModalLiveTimer) {
        clearInterval(snmpModalLiveTimer);
        snmpModalLiveTimer = null;
    }
    if (chk && chk.checked && currentSnmpDeviceId) {
        snmpModalLiveTimer = setInterval(() => {
            const modal = document.getElementById("snmp-modal");
            if (modal && !modal.hidden && currentSnmpDeviceId) {
                loadDeviceMetricsIntoModal(currentSnmpDeviceId);
            }
        }, 30000);
    }
}

function updateSnmpAutoPollUi(dev) {
    const badge = document.getElementById("snmp-auto-status-badge");
    const startBtn = document.getElementById("snmp-auto-start-btn");
    const stopBtn = document.getElementById("snmp-auto-stop-btn");
    if (!badge || !startBtn || !stopBtn) return;

    if (dev.snmp_auto_poll) {
        badge.className = "badge badge-up";
        badge.textContent = dev.snmp_auto_until
            ? `🟢 ATIVA (até ${dev.snmp_auto_until})`
            : "🟢 ATIVA (Contínua)";
        startBtn.textContent = "🔄 Atualizar Prazo";
        stopBtn.hidden = false;
    } else {
        badge.className = "badge badge-inactive";
        badge.textContent = "⚪ DESATIVADA (Apenas Manual)";
        startBtn.textContent = "▶ Ativar Coleta Automática";
        stopBtn.hidden = true;
    }
}

async function setDeviceSnmpAutoPoll(enable) {
    if (!currentSnmpDeviceId) return;
    const durSel = document.getElementById("snmp-auto-duration");
    const durationHours = durSel ? Number(durSel.value) : 24;
    const startBtn = document.getElementById("snmp-auto-start-btn");
    const stopBtn = document.getElementById("snmp-auto-stop-btn");

    if (startBtn) startBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = true;

    try {
        await apiPost(`/api/devices/${currentSnmpDeviceId}/snmp/auto-poll`, {
            enabled: Boolean(enable),
            duration_hours: durationHours,
        });
        await Promise.all([refreshDevices(), loadDeviceMetricsIntoModal(currentSnmpDeviceId)]);
    } catch (e) {
        alert(e.message);
    } finally {
        if (startBtn) startBtn.disabled = false;
        if (stopBtn) stopBtn.disabled = false;
    }
}

async function openSnmpModal(deviceId) {
    currentSnmpDeviceId = deviceId;
    const dev = allDevices.find(d => d.id === deviceId);
    if (!dev) return;

    document.getElementById("snmp-modal-title").textContent = `Métricas & SNMP — ${dev.name}`;
    document.getElementById("snmp-modal-subtitle").textContent = `${dev.ip} • ${dev.ros_version_detail ? 'RouterOS ' + dev.ros_version_detail : dev.ros_version.toUpperCase()} • Status SNMP: ${dev.snmp_status}`;
    const defaultComm = (!dev.snmp_enabled && dev.snmp_community === "public") ? "@BKP2712" : (dev.snmp_community || "@BKP2712");
    document.getElementById("prov-snmp-community").value = defaultComm;
    const fb = document.getElementById("prov-snmp-feedback");
    fb.hidden = true;
    fb.textContent = "";

    updateSnmpAutoPollUi(dev);
    openModal("snmp-modal");
    toggleSnmpModalLiveRefresh();
    await loadDeviceMetricsIntoModal(deviceId);
}

function renderSnmpReportSummary(summary) {
    const grid = document.getElementById("snmp-report-summary-grid");
    const winInfo = document.getElementById("snmp-report-window-info");
    if (!grid) return;

    if (!summary || !summary.samples_count) {
        if (winInfo) winInfo.textContent = "(0 coletas registradas neste período)";
        grid.innerHTML = `<div style="grid-column: 1 / -1; color:#64748b; text-align:center; padding:6px;">Nenhuma amostra coletada neste período. Ative a Coleta Automática acima ou clique em "Coletar Agora".</div>`;
        return;
    }

    if (winInfo) {
        winInfo.textContent = `(${summary.samples_count} coletas • ${summary.period_start} até ${summary.period_end})`;
    }

    const boxStyle = "background:#fff; border:1px solid #cbd5e1; border-radius:6px; padding:8px 10px;";
    grid.innerHTML = `
        <div style="${boxStyle}">
            <div style="color:#64748b; font-size:11px;">CPU (Média / Pico)</div>
            <div style="font-size:14px; font-weight:700; color:#0f172a; margin-top:2px;">
                ${summary.cpu_avg != null ? summary.cpu_avg + "%" : "-"} / <span style="color:#dc2626;">${summary.cpu_max != null ? summary.cpu_max + "%" : "-"}</span>
            </div>
            ${summary.cpu_peak_at ? `<small style="color:#94a3b8; font-size:10px;">Pico: ${escapeHtml(summary.cpu_peak_at.slice(5, 16))}</small>` : ""}
        </div>
        <div style="${boxStyle}">
            <div style="color:#64748b; font-size:11px;">Memória (Média / Pico)</div>
            <div style="font-size:14px; font-weight:700; color:#0f172a; margin-top:2px;">
                ${summary.mem_avg != null ? summary.mem_avg + "%" : "-"} / <span style="color:#7c3aed;">${summary.mem_max != null ? summary.mem_max + "%" : "-"}</span>
            </div>
            ${summary.mem_peak_at ? `<small style="color:#94a3b8; font-size:10px;">Pico: ${escapeHtml(summary.mem_peak_at.slice(5, 16))}</small>` : ""}
        </div>
        <div style="${boxStyle}">
            <div style="color:#64748b; font-size:11px;">Download RX (Média / Pico)</div>
            <div style="font-size:14px; font-weight:700; color:#15803d; margin-top:2px;">
                ${fmtBps(summary.rx_avg_bps)} / ${fmtBps(summary.rx_max_bps)}
            </div>
            ${summary.rx_peak_at ? `<small style="color:#94a3b8; font-size:10px;">Pico: ${escapeHtml(summary.rx_peak_at.slice(5, 16))}</small>` : ""}
        </div>
        <div style="${boxStyle}">
            <div style="color:#64748b; font-size:11px;">Upload TX (Média / Pico)</div>
            <div style="font-size:14px; font-weight:700; color:#0369a1; margin-top:2px;">
                ${fmtBps(summary.tx_avg_bps)} / ${fmtBps(summary.tx_max_bps)}
            </div>
            ${summary.tx_peak_at ? `<small style="color:#94a3b8; font-size:10px;">Pico: ${escapeHtml(summary.tx_peak_at.slice(5, 16))}</small>` : ""}
        </div>
        <div style="${boxStyle}">
            <div style="color:#64748b; font-size:11px;">Latência ICMP (Média / Pico)</div>
            <div style="font-size:14px; font-weight:700; color:#0f172a; margin-top:2px;">
                ${summary.lat_avg != null ? summary.lat_avg + " ms" : "-"} / ${summary.lat_max != null ? summary.lat_max + " ms" : "-"}
            </div>
        </div>
    `;
}

function exportDeviceMetricsCsv() {
    if (!currentSnmpDeviceId) return;
    const hours = document.getElementById("snmp-report-hours")?.value || "24";
    window.open(`/api/devices/${currentSnmpDeviceId}/metrics/export?hours=${encodeURIComponent(hours)}`, "_blank");
}

function copyDeviceAnalysisSummary() {
    if (!lastLoadedMetricsData || !lastLoadedMetricsData.device) return;
    const d = lastLoadedMetricsData.device;
    const s = lastLoadedMetricsData.summary || {};
    const txt = [
        `📊 RELATÓRIO DE ANÁLISE SNMP — ${d.name} (${d.ip})`,
        `RouterOS: ${d.ros_version_detail || d.ros_version} | Modelo: ${d.board_name || "-"}`,
        `Período: ${s.period_start || "-"} até ${s.period_end || "-"} (${s.samples_count || 0} coletas)`,
        `• Uptime Atual: ${d.uptime_str || "-"}`,
        `• CPU: Média ${s.cpu_avg ?? "-"}% | Pico ${s.cpu_max ?? "-"}% (${s.cpu_peak_at || "-"})`,
        `• Memória: Média ${s.mem_avg ?? "-"}% | Pico ${s.mem_max ?? "-"}%`,
        `• Download (RX): Média ${fmtBps(s.rx_avg_bps)} | Pico ${fmtBps(s.rx_max_bps)} (${s.rx_peak_at || "-"})`,
        `• Upload (TX): Média ${fmtBps(s.tx_avg_bps)} | Pico ${fmtBps(s.tx_max_bps)} (${s.tx_peak_at || "-"})`,
        `• Latência ICMP: Média ${s.lat_avg ?? "-"} ms | Pico ${s.lat_max ?? "-"} ms`,
    ].join("\n");
    navigator.clipboard?.writeText(txt);
    alert("Resumo do relatório copiado para a área de transferência!");
}

async function clearDeviceMetricsHistory() {
    if (!currentSnmpDeviceId) return;
    if (!confirm("Deseja zerar o histórico de métricas coletadas deste equipamento para iniciar uma nova análise limpa?")) return;
    try {
        await apiDelete(`/api/devices/${currentSnmpDeviceId}/metrics`);
        await loadDeviceMetricsIntoModal(currentSnmpDeviceId);
    } catch (e) {
        alert(e.message);
    }
}

async function loadDeviceMetricsIntoModal(deviceId) {
    try {
        const hours = document.getElementById("snmp-report-hours")?.value || "24";
        const data = await apiGet(`/api/devices/${deviceId}/metrics?hours=${encodeURIComponent(hours)}&limit=500`);
        lastLoadedMetricsData = data;
        const d = data.device;
        const series = data.series || [];

        updateSnmpAutoPollUi(d);

        document.getElementById("metric-uptime").textContent = d.uptime_str || "-";
        document.getElementById("metric-cpu").textContent = d.cpu_load != null ? `${d.cpu_load}%` : "-";
        document.getElementById("metric-mem").textContent = d.memory_used_pct != null ? `${Number(d.memory_used_pct).toFixed(1)}%` : "-";
        document.getElementById("metric-mem-detail").textContent = d.memory_total_mb ? `${d.memory_used_mb || 0} / ${d.memory_total_mb} MB` : "";
        document.getElementById("metric-traffic").textContent = `↓ ${fmtBps(d.rx_bps)} | ↑ ${fmtBps(d.tx_bps)}`;

        renderSnmpReportSummary(data.summary);
        renderSnmpCharts(series);
        renderInterfacesTable(d.interfaces || []);
    } catch (e) {
        console.error("Erro ao carregar métricas:", e);
    }
}

function renderSvgLineChart(points, keys, colors, labels, unitSuffix = "") {
    if (!points || points.length === 0) {
        return `<div style="padding:25px; text-align:center; color:#94a3b8; font-size:12px;">Sem histórico suficiente. Clique em "Configurar e Validar SNMP" ou "Coletar Agora".</div>`;
    }
    const width = 380, height = 120, pad = 18;
    const allVals = [];
    keys.forEach(k => {
        points.forEach(p => {
            if (p[k] != null) allVals.push(Number(p[k]));
        });
    });
    const maxV = allVals.length ? Math.max(...allVals, 1) : 100;
    const minV = 0;
    const range = (maxV - minV) || 1;
    const dx = points.length > 1 ? (width - pad * 2) / (points.length - 1) : 0;

    const polylines = keys.map((k, idx) => {
        const coords = [];
        points.forEach((p, i) => {
            if (p[k] != null) {
                const x = (pad + i * dx).toFixed(1);
                const y = (height - pad - ((Number(p[k]) - minV) / range) * (height - pad * 2)).toFixed(1);
                coords.push(`${x},${y}`);
            }
        });
        if (!coords.length) return "";
        return `<polyline fill="none" stroke="${colors[idx]}" stroke-width="2" points="${coords.join(" ")}"></polyline>`;
    }).join("");

    const legend = labels.map((lbl, idx) => `<span style="color:${colors[idx]}; font-weight:bold; font-size:11px; margin-right:10px;">● ${escapeHtml(lbl)}</span>`).join("");

    return `
        <div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <div>${legend}</div>
                <small style="color:#64748b; font-size:11px;">Topo: ${maxV.toFixed(0)}${unitSuffix}</small>
            </div>
            <svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:4px;">
                ${polylines}
            </svg>
        </div>
    `;
}

function renderSnmpCharts(series) {
    const cpuMemEl = document.getElementById("chart-cpu-mem");
    const trafLatEl = document.getElementById("chart-traffic-lat");
    if (cpuMemEl) {
        cpuMemEl.innerHTML = renderSvgLineChart(
            series,
            ["cpu_load", "memory_used_pct"],
            ["#007bff", "#9333ea"],
            ["CPU %", "Memória %"],
            "%"
        );
    }
    if (trafLatEl) {
        // Convert bps to Kbps for chart scaling alongside latency_ms
        const scaled = series.map(p => ({
            rx_kbps: p.rx_bps ? Math.round(p.rx_bps / 1000) : 0,
            tx_kbps: p.tx_bps ? Math.round(p.tx_bps / 1000) : 0,
            latency_ms: p.latency_ms,
        }));
        trafLatEl.innerHTML = renderSvgLineChart(
            scaled,
            ["rx_kbps", "tx_kbps", "latency_ms"],
            ["#16a34a", "#0ea5e9", "#f59e0b"],
            ["RX (Kbps)", "TX (Kbps)", "Latência (ms)"],
            ""
        );
    }
}

function renderInterfacesTable(interfaces) {
    const tbody = document.getElementById("snmp-interfaces-tbody");
    if (!tbody) return;
    if (!interfaces || interfaces.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#888; padding:14px;">Nenhuma interface coletada ainda.</td></tr>`;
        return;
    }
    tbody.innerHTML = interfaces.map(iface => `
        <tr>
            <td><strong>${escapeHtml(iface.name)}</strong></td>
            <td><span class="badge ${iface.running ? 'badge-up' : 'badge-inactive'}">${iface.running ? 'RUNNING' : 'DOWN'}</span></td>
            <td>${fmtBps(iface.rx_bps)}</td>
            <td>${fmtBps(iface.tx_bps)}</td>
            <td>${fmtBytes(iface.rx_bytes)}</td>
            <td>${fmtBytes(iface.tx_bytes)}</td>
        </tr>
    `).join("");
}

async function provisionSnmpViaSsh() {
    if (!currentSnmpDeviceId) return;
    const btn = document.getElementById("prov-snmp-btn");
    const fb = document.getElementById("prov-snmp-feedback");
    const community = document.getElementById("prov-snmp-community").value.trim() || "public";
    const allowedIp = document.getElementById("prov-snmp-allowed-ip")?.value.trim() || "38.225.221.159";
    const allowFw = document.getElementById("prov-snmp-firewall").checked;

    btn.disabled = true;
    btn.textContent = "Configurando via SSH...";
    fb.hidden = false;
    fb.style.color = "#0369a1";
    fb.textContent = `Conectando via SSH ao equipamento para restringir SNMP a ${allowedIp} (e bloquear demais IPs)...`;

    try {
        const res = await apiPost(`/api/devices/${currentSnmpDeviceId}/snmp/provision`, {
            snmp_community: community,
            allowed_ip: allowedIp,
            allow_firewall: allowFw,
        });
        fb.style.color = res.ok ? "#15803d" : "#b91c1c";
        fb.textContent = res.ok ? `✅ ${res.message}` : `❌ ${res.message}`;
        await Promise.all([refreshDevices(), loadDeviceMetricsIntoModal(currentSnmpDeviceId), refreshSummary()]);
    } catch (e) {
        fb.style.color = "#b91c1c";
        fb.textContent = `❌ Erro: ${e.message}`;
    } finally {
        btn.disabled = false;
        btn.textContent = "Configurar e Validar SNMP via SSH";
    }
}

async function pollDeviceSnmpNow() {
    if (!currentSnmpDeviceId) return;
    const btn = document.getElementById("snmp-poll-now-btn");
    btn.disabled = true;
    btn.textContent = "Coletando...";
    try {
        await apiPost(`/api/devices/${currentSnmpDeviceId}/snmp/poll-now`);
        await Promise.all([refreshDevices(), loadDeviceMetricsIntoModal(currentSnmpDeviceId), refreshSummary()]);
    } catch (e) {
        alert(e.message);
    } finally {
        btn.disabled = false;
        btn.textContent = "Coletar Agora";
    }
}

// ---------- License Management (Lightweight Key Control) ----------

async function refreshLicenses() {
    const tbody = document.getElementById("licenses-tbody");
    if (!tbody) return;
    try {
        const licenses = await apiGet("/api/licenses");
        if (licenses.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #888; padding: 20px;">Nenhuma licença cadastrada. Clique em "+ Nova Licença" para começar.</td></tr>`;
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

            let lastSeenDisplay = '<span style="color:#999; font-size:12px;">Nunca</span>';
            if (lic.last_check_at) {
                const subDetails = [lic.last_ip, lic.last_hostname].filter(Boolean).join(" • ");
                lastSeenDisplay = `
                    <div style="font-weight: 500;">${escapeHtml(lic.last_check_relative)}</div>
                    ${subDetails ? `<small style="color: #666; font-size: 11px;">${escapeHtml(subDetails)}</small>` : ''}
                `;
            }

            const isBlocked = lic.status === "BLOCKED";
            const toggleBtnText = isBlocked ? "Desbloquear" : "Bloquear";
            const toggleBtnClass = isBlocked ? "btn-warning" : "btn-secondary";

            return `
                <tr class="${isBlocked ? 'row-inactive' : ''}">
                    <td>
                        <strong style="color: #007bff;">${escapeHtml(lic.client_name)}</strong>
                        ${lic.is_online ? '<span class="badge" style="background:#dcfce7; color:#15803d; border:1px solid #bbf7d0; font-size:10px; margin-left:6px;" title="Conectado em tempo real">● Online</span>' : ''}
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
                    <td class="actions-cell">
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
    if (!confirm(`Remover permanentemente a licença de "${name}"?`)) return;
    try {
        await apiDelete(`/api/licenses/${id}`);
        refreshLicenses();
        refreshSummary();
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

// ---------- Dashboard Summary ----------

async function refreshSummary() {
    const s = await apiGet("/api/summary");
    document.getElementById("stat-devices-total").textContent = s.devices_total;
    document.getElementById("stat-ros-breakdown").textContent = `RouterOS v6: ${s.ros_v6} | v7: ${s.ros_v7}`;
    document.getElementById("stat-targets-up").textContent = s.targets_up;
    document.getElementById("stat-targets-down").textContent = s.targets_down;
    document.getElementById("stat-avg-latency").textContent = fmtLatency(s.avg_latency_ms);
    document.getElementById("stat-backups-ok").textContent = `${s.backups_ok_today} / ${s.backup_devices_total}`;
    document.getElementById("stat-backups-sub").textContent = `Falhas recentes: ${s.backups_failed_today}`;
    document.getElementById("stat-snmp-ok").textContent = `${s.snmp_ok} / ${s.snmp_devices_total}`;
    document.getElementById("stat-snmp-sub").textContent = `SSH habilitado: ${s.ssh_devices_total} disp.`;
    document.getElementById("stat-licenses-active").textContent = `${s.licenses_active} / ${s.licenses_total}`;
    document.getElementById("stat-licenses-sub").textContent = `Bloqueadas: ${s.licenses_blocked}`;
}

// ---------- Settings & Telegram Destinations ----------

async function loadSettings() {
    const s = await apiGet("/api/settings");
    ["telegram-form", "monitoring-form", "backup-form"].forEach(formId => {
        const form = document.getElementById(formId);
        if (!form) return;
        Array.from(form.elements).forEach(el => {
            if (el.name && s[el.name] !== undefined) el.value = s[el.name];
        });
    });
}

async function saveAllSettings() {
    const payload = {};
    ["telegram-form", "monitoring-form", "backup-form"].forEach(formId => {
        const form = document.getElementById(formId);
        if (!form) return;
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

async function refreshDestinations() {
    telegramDestinations = await apiGet("/api/telegram_destinations");
    const tbody = document.getElementById("dests-tbody");
    if (tbody) {
        tbody.innerHTML = telegramDestinations.map(d => `
            <tr>
                <td>${escapeHtml(d.name)}</td>
                <td><code>${escapeHtml(d.chat_id)}</code></td>
                <td class="actions-cell">
                    <button class="btn btn-primary btn-sm" onclick='openDestModal(${JSON.stringify(d)})'>Editar</button>
                    <button class="btn btn-danger btn-sm" onclick="deleteDest(${d.id}, '${escapeHtml(d.name)}')">Remover</button>
                </td>
            </tr>
        `).join("");
    }

    const select = document.getElementById("device-telegram-select");
    if (select) {
        const currentVal = select.value;
        select.innerHTML = `<option value="">Padrão do Sistema</option>` +
            telegramDestinations.map(d => `<option value="${d.id}">${escapeHtml(d.name)}</option>`).join("");
        select.value = currentVal;
    }
}

function openDestModal(dest = null) {
    const form = document.getElementById("dest-form");
    form.reset();
    document.getElementById("dest-modal-title").innerText = dest ? "Editar Destino" : "Novo Destino Telegram";
    if (dest) {
        form.id.value = dest.id;
        form.name.value = dest.name;
        form.token.value = dest.token;
        form.chat_id.value = dest.chat_id;
    } else {
        form.id.value = "";
    }
    openModal("dest-modal");
}

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("dest-form");
    if (form) {
        form.addEventListener("submit", async e => {
            e.preventDefault();
            const data = Object.fromEntries(new FormData(e.target).entries());
            if (data.id) {
                await apiPut(`/api/telegram_destinations/${data.id}`, data);
            } else {
                await apiPost("/api/telegram_destinations", data);
            }
            closeModal("dest-modal");
            refreshDestinations();
        });
    }
});

async function deleteDest(id, name) {
    if (!confirm(`Remover destino "${name}"? Isso removerá a associação de qualquer dispositivo que o use.`)) return;
    await apiDelete(`/api/telegram_destinations/${id}`);
    refreshDestinations();
}

// ---------- Bootstrap ----------

let pollTimer = null;

async function refreshAll() {
    await Promise.all([
        refreshSummary(),
        refreshDevices(),
        refreshBackupHistory(),
        refreshCommandLogs(),
        refreshLicenses(),
        refreshDestinations(),
    ]);
}

document.addEventListener("DOMContentLoaded", async () => {
    initTabs();
    try {
        const savedTab = localStorage.getItem("bkpprovider_tab");
        if (savedTab && document.getElementById(savedTab)) switchTab(savedTab);
    } catch (e) { /* ignore */ }

    await loadQuickActionsCatalog();
    await loadSettings();
    await refreshAll();

    const settings = await apiGet("/api/settings");
    const intervalMs = Math.max(parseInt(settings.ping_interval_seconds, 10) || 30, 10) * 1000;
    pollTimer = setInterval(refreshAll, intervalMs);
});

// ---------- OLT GPON (Cianet) ----------

async function checkOltStatus() {
    const badge = document.getElementById("olt-status-badge");
    if (badge) badge.textContent = "Verificando...";
    try {
        const res = await apiGet("/api/olt/status");
        if (badge) {
            if (res.ok) {
                badge.className = "badge badge-up";
                badge.textContent = `🟢 Conectada (${res.host} • ${res.model})`;
            } else {
                badge.className = "badge badge-down";
                badge.textContent = `🔴 Offline (${res.error || "Erro"})`;
            }
        }
    } catch (e) {
        if (badge) {
            badge.className = "badge badge-down";
            badge.textContent = `🔴 Erro: ${e.message}`;
        }
    }
}

async function searchOltOnt() {
    const input = document.getElementById("olt-search-input");
    const container = document.getElementById("olt-search-result");
    if (!input || !container) return;
    const q = input.value.trim();
    if (!q) {
        alert("Digite o MAC ou Serial da ONU para consultar.");
        return;
    }
    container.style.display = "block";
    container.innerHTML = `<div style="padding: 16px; text-align: center; color: #666;">Consultando OLT Cianet via VPN... aguarde.</div>`;
    try {
        const res = await apiGet(`/api/olt/search?q=${encodeURIComponent(q)}`);
        const items = res.items || [];
        if (items.length === 0) {
            container.innerHTML = `<div style="padding: 14px; background: #fff1f2; border: 1px solid #fecdd3; border-radius: 6px; color: #9f1239;">Nenhuma ONU encontrada com o serial/MAC "<b>${escapeHtml(q)}</b>".</div>`;
            return;
        }
        container.innerHTML = items.map(ont => {
            const rx = parseFloat(ont.rx_dbm);
            let rxColor = "#22c55e";
            let rxLabel = "Ótimo";
            if (isNaN(rx)) {
                rxColor = "#64748b";
                rxLabel = "--";
            } else if (rx < -28.0) {
                rxColor = "#ef4444";
                rxLabel = "Crítico / Baixo";
            } else if (rx < -25.0) {
                rxColor = "#f59e0b";
                rxLabel = "Atenção";
            }

            const isOnline = ont.status === "Online";
            return `
                <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 12px; background: #f8fafc;">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:10px;">
                        <div>
                            <span class="badge ${isOnline ? 'badge-up' : 'badge-down'}" style="font-size:13px; margin-right:8px;">${escapeHtml(ont.status)}</span>
                            <span style="font-size: 16px; font-weight: bold; font-family: monospace;">${escapeHtml(ont.sn)}</span>
                            <span style="color: #64748b; font-size: 13px; margin-left: 8px;">(Porta PON ${ont.port} • ONT-ID ${ont.ont_id})</span>
                        </div>
                        <button type="button" class="btn btn-danger btn-sm" onclick="deauthorizeOnt(${ont.port}, ${ont.ont_id}, '${escapeHtml(ont.sn)}')">Desautorizar ONU</button>
                    </div>

                    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-top: 14px;">
                        <div style="background: #ffffff; padding: 10px; border-radius: 6px; border: 1px solid #e2e8f0; text-align: center;">
                            <div style="font-size: 11px; color: #64748b; text-transform: uppercase;">Rx Óptico (ONU)</div>
                            <div style="font-size: 18px; font-weight: bold; color: ${rxColor}; margin-top: 4px;">${ont.rx_dbm ? ont.rx_dbm + ' dBm' : '--'}</div>
                            <small style="font-size: 10px; color: ${rxColor}; font-weight: 600;">${rxLabel}</small>
                        </div>
                        <div style="background: #ffffff; padding: 10px; border-radius: 6px; border: 1px solid #e2e8f0; text-align: center;">
                            <div style="font-size: 11px; color: #64748b; text-transform: uppercase;">Tx Óptico (ONU)</div>
                            <div style="font-size: 18px; font-weight: bold; color: #1e293b; margin-top: 4px;">${ont.tx_dbm ? ont.tx_dbm + ' dBm' : '--'}</div>
                            <small style="font-size: 10px; color: #64748b;">Potência de Envio</small>
                        </div>
                        <div style="background: #ffffff; padding: 10px; border-radius: 6px; border: 1px solid #e2e8f0; text-align: center;">
                            <div style="font-size: 11px; color: #64748b; text-transform: uppercase;">Sinal na OLT</div>
                            <div style="font-size: 18px; font-weight: bold; color: #1e293b; margin-top: 4px;">${ont.olt_rx_dbm ? ont.olt_rx_dbm + ' dBm' : '--'}</div>
                            <small style="font-size: 10px; color: #64748b;">Rx na OLT</small>
                        </div>
                        <div style="background: #ffffff; padding: 10px; border-radius: 6px; border: 1px solid #e2e8f0; text-align: center;">
                            <div style="font-size: 11px; color: #64748b; text-transform: uppercase;">Temperatura / Tensão</div>
                            <div style="font-size: 15px; font-weight: bold; color: #1e293b; margin-top: 6px;">${ont.temp_c ? ont.temp_c + '°C' : '--'} | ${ont.voltage_v ? ont.voltage_v + 'V' : '--'}</div>
                            <small style="font-size: 10px; color: #64748b;">Diagnóstico DDM</small>
                        </div>
                    </div>
                </div>
            `;
        }).join("");
    } catch (e) {
        container.innerHTML = `<div style="padding: 14px; background: #fff1f2; border: 1px solid #fecdd3; border-radius: 6px; color: #9f1239;">Erro ao consultar OLT: ${escapeHtml(e.message)}</div>`;
    }
}

async function refreshOltUnauthorized() {
    const container = document.getElementById("olt-unauth-container");
    if (!container) return;
    container.innerHTML = `<div style="padding: 12px; color: #666;">Verificando ONUs pendentes no autofind...</div>`;
    try {
        const res = await apiGet("/api/olt/unauthorized");
        const items = res.items || [];
        if (items.length === 0) {
            container.innerHTML = `<div style="padding: 12px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; color: #166534;">✅ Nenhuma ONU aguardando autorização no momento (autofind limpo).</div>`;
            return;
        }
        container.innerHTML = `
            <table style="width:100%; border-collapse:collapse; margin-top:10px;">
                <thead>
                    <tr style="background:#f1f5f9; text-align:left;">
                        <th style="padding:8px;">Dados da ONU</th>
                        <th style="padding:8px; text-align:right;">Ação</th>
                    </tr>
                </thead>
                <tbody>
                    ${items.map(u => {
                        const parts = u.parts || [];
                        const pNum = parts[1] || "1";
                        const snVal = parts[2] || "";
                        return `
                            <tr style="border-bottom:1px solid #e2e8f0;">
                                <td style="padding:8px; font-family:monospace;">${escapeHtml(u.raw || "")}</td>
                                <td style="padding:8px; text-align:right;">
                                    <button type="button" class="btn btn-primary btn-sm" onclick="authorizeOnt(${pNum}, '${escapeHtml(snVal)}')">Autorizar ONU</button>
                                </td>
                            </tr>
                        `;
                    }).join("")}
                </tbody>
            </table>
        `;
    } catch (e) {
        container.innerHTML = `<div style="color: #ef4444; padding: 10px;">Erro: ${escapeHtml(e.message)}</div>`;
    }
}

async function authorizeOnt(port, sn) {
    if (!confirm(`Deseja autorizar a ONU ${sn} na porta PON ${port}?`)) return;
    try {
        const res = await apiPost("/api/olt/authorize", { port, sn });
        alert(res.message || "ONU autorizada com sucesso!");
        refreshOltUnauthorized();
    } catch (e) {
        alert(e.message);
    }
}

async function deauthorizeOnt(port, ontId, sn) {
    if (!confirm(`Tem certeza que deseja DESAUTORIZAR/REMOVER a ONU ${sn || ''} (ID ${ontId}) da porta PON ${port}?`)) return;
    try {
        const res = await apiPost("/api/olt/deauthorize", { port, ont_id: ontId });
        alert(res.message || "ONU desautorizada com sucesso!");
        searchOltOnt();
    } catch (e) {
        alert(e.message);
    }
}
