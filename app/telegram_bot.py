import asyncio
import html
import re
import time
import unicodedata

import aiohttp

from app.crypto import decrypt_secret
from app.db import get_db, get_setting, prune_command_logs
from app.mikrotik import (
    SSH_SEMAPHORE,
    _connect_ssh,
    _exec_ssh_cmd,
    _parse_ros_detail_blocks,
    execute_device_command,
    run_backup_for_device,
)


def _normalize_slug(text: str) -> str:
    """Normalizes a device name into a lowercase ascii slug with underscores."""
    if not text:
        return ""
    norm = unicodedata.normalize("NFKD", str(text)).encode("ascii", "ignore").decode("ascii")
    norm = norm.lower().strip()
    norm = re.sub(r"[^a-z0-9]+", "_", norm).strip("_")
    return norm


def _device_command_slug(name: str) -> str:
    """Returns a concise Telegram slash-command slug (max 32 chars, a-z0-9_)."""
    slug = _normalize_slug(name)
    # Shorten common suffixes like '_via_gnet' if needed, while keeping full match in resolver
    if slug.endswith("_via_gnet"):
        slug = slug[: -len("_via_gnet")]
    return slug[:30]


def _fmt_bps(bps_val) -> str:
    try:
        bps = float(bps_val or 0)
    except (ValueError, TypeError):
        bps = 0.0
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Mbps"
    if bps >= 1_000:
        return f"{bps / 1_000:.1f} Kbps"
    return f"{int(bps)} bps"


def _fmt_bytes(bytes_val) -> str:
    try:
        val = float(bytes_val or 0)
    except (ValueError, TypeError):
        return "0 B"
    if val >= 1_073_741_824 * 1024:
        return f"{val / (1024**4):.2f} TB"
    if val >= 1_073_741_824:
        return f"{val / (1024**3):.2f} GB"
    if val >= 1_048_576:
        return f"{val / (1024**2):.2f} MB"
    if val >= 1024:
        return f"{val / 1024:.1f} KB"
    return f"{int(val)} B"


def _fmt_uptime_ptbr(raw: str) -> str:
    if not raw or raw == "-":
        return "-"
    s = raw.strip().lower()

    weeks = 0
    days = 0
    hours = 0
    minutes = 0
    seconds = 0

    m_w = re.search(r"(\d+)\s*w", s)
    if m_w:
        weeks = int(m_w.group(1))
    m_d = re.search(r"(\d+)\s*d", s)
    if m_d:
        days = int(m_d.group(1))

    rest = re.sub(r"^\s*(?:\d+w)?\s*(?:\d+d)?\s*", "", s)

    m_time = re.match(r"^(\d{1,2}):(\d{2})(?::(\d{2}))?", rest)
    if m_time:
        hours = int(m_time.group(1))
        minutes = int(m_time.group(2))
        if m_time.group(3):
            seconds = int(m_time.group(3))
    else:
        m_h = re.search(r"(\d+)\s*h", rest)
        if m_h:
            hours = int(m_h.group(1))
        m_m = re.search(r"(\d+)\s*m", rest)
        if m_m:
            minutes = int(m_m.group(1))
        m_s = re.search(r"(\d+)\s*s", rest)
        if m_s:
            seconds = int(m_s.group(1))

    parts = []
    if weeks > 0:
        parts.append(f"{weeks} semana" if weeks == 1 else f"{weeks} semanas")
    if days > 0:
        parts.append(f"{days} dia" if days == 1 else f"{days} dias")
    if hours > 0:
        parts.append(f"{hours} hora" if hours == 1 else f"{hours} horas")
    if minutes > 0:
        parts.append(f"{minutes} min")
        if hours == 0 and seconds > 0:
            parts.append(f"{seconds} seg")
    elif not parts and seconds > 0:
        parts.append(f"{seconds} seg")

    if not parts:
        return raw

    if len(parts) == 1:
        return parts[0]
    return ", ".join(parts[:-1]) + " e " + parts[-1]


def _safe_pre(text: str, max_len: int = 3300) -> str:
    cleaned = (text or "").strip()
    if not cleaned:
        cleaned = "(Sem saída)"
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "\n... [saída truncada]"
    return f"<pre>{html.escape(cleaned)}</pre>"


def _device_has_olt(dev: dict | None = None, dev_id: int | None = None) -> bool:
    if dev:
        if dev.get("id") == 17 or dev.get("telegram_destination_id") == 3 or "marcos" in str(dev.get("name", "")).lower():
            return True
    if dev_id == 17:
        return True
    if dev_id:
        try:
            conn = get_db()
            row = conn.execute("SELECT id, name, telegram_destination_id FROM devices WHERE id = ?", (dev_id,)).fetchone()
            conn.close()
            if row:
                d_row = dict(row)
                return d_row.get("id") == 17 or d_row.get("telegram_destination_id") == 3 or "marcos" in str(d_row.get("name", "")).lower()
        except Exception:
            pass
    return False


def _device_keyboard(dev_id: int, dev_type: str = "mikrotik", has_olt: bool | None = None) -> dict:
    if has_olt is None:
        has_olt = _device_has_olt(dev_id=dev_id)

    if dev_type == "provedor":
        rows = [
            [
                {"text": "👥 Clientes", "callback_data": f"devcmd:{dev_id}:clientes"},
                {"text": "📊 Consumo Geral", "callback_data": f"devcmd:{dev_id}:consumo"},
            ],
            [
                {"text": "💡 Sinal Gbic", "callback_data": f"devcmd:{dev_id}:gbic"},
                {"text": "🌐 Ping Internet", "callback_data": f"devcmd:{dev_id}:pingnet"},
            ],
            [
                {"text": "💻 Recursos & CPU", "callback_data": f"devcmd:{dev_id}:recursos"},
                {"text": "📜 Logs Recentes", "callback_data": f"devcmd:{dev_id}:logs"},
            ],
        ]
        if has_olt:
            rows.append([
                {"text": "📟 OLT: Não Autorizadas", "callback_data": f"devcmd:{dev_id}:olt_unauth"},
                {"text": "🔍 OLT: Buscar ONU", "callback_data": f"devcmd:{dev_id}:olt_search"},
            ])
        return {"inline_keyboard": rows}
    return {
        "inline_keyboard": [
            [
                {"text": "🌐 IPs", "callback_data": f"devcmd:{dev_id}:ips"},
                {"text": "🛣️ Rotas Ativas", "callback_data": f"devcmd:{dev_id}:rotas"},
            ],
            [
                {"text": "📊 Consumo", "callback_data": f"devcmd:{dev_id}:consumo"},
                {"text": "🔌 Portas", "callback_data": f"devcmd:{dev_id}:portas"},
            ],
            [
                {"text": "💻 Recursos", "callback_data": f"devcmd:{dev_id}:recursos"},
                {"text": "📜 Logs", "callback_data": f"devcmd:{dev_id}:logs"},
            ],
            [
                {"text": "🧱 Listar Firewall (NAT)", "callback_data": f"devcmd:{dev_id}:firewall"},
            ],
        ]
    }


def _parse_ethernet_monitor_blocks(text: str) -> list[dict]:
    items = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line == "---IF---":
            if current and "name" in current:
                items.append(current)
            current = {}
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip().lower()
            v = v.strip()
            # Ignore hex offset lines from eeprom dump (e.g. "0000", "0010", etc.)
            if re.match(r"^[0-9a-f]{4}$", k):
                continue
            if k == "name" and current and "name" in current:
                items.append(current)
                current = {}
            current[k] = v
    if current and "name" in current:
        items.append(current)
    return items


def _inspect_device_special_sync(
    ip: str,
    port: int,
    username: str,
    password_plain: str,
    ros_version: str,
    mode: str,
) -> tuple[bool, dict]:
    """
    Executes rich multi-part SSH inspections for Telegram:
    - mode == 'links': default routes + monitor routes + netwatch + live RX/TX bps on running interfaces
    - mode == 'consumo': live RX/TX bps on all running interfaces + CPU/Memory/Uptime
    - mode == 'portas': interface status/stats + ethernet details + IP services ports
    - mode in ('gbic', 'sfp'): SFP optical monitor (DDM rx/tx power, temp, voltage) + live traffic
    """
    ssh = None
    try:
        ssh = _connect_ssh(ip, port, username, password_plain, timeout=12)
        if mode == "links":
            cmd = (
                ':put "===SEC:ROUTES==="; /ip route print detail without-paging; '
                ':put "===SEC:NW==="; /tool netwatch print detail without-paging; '
                ':put "===SEC:TRAF==="; '
                ':foreach i in=[/interface find running=yes and type!="pppoe-in"] do={ '
                ':local n [/interface get $i name]; '
                ':local m [/interface monitor-traffic $i once as-value]; '
                ':put ("IF=" . $n . "|RX=" . ($m->"rx-bits-per-second") . "|TX=" . ($m->"tx-bits-per-second")) '
                '}'
            )
            _, raw_out, _ = _exec_ssh_cmd(ssh, cmd, timeout=18)
        elif mode == "consumo":
            cmd = (
                ':put "===SEC:RES==="; /system resource print without-paging; '
                ':put "===SEC:TRAF==="; '
                ':foreach i in=[/interface find running=yes and type!="pppoe-in"] do={ '
                ':local n [/interface get $i name]; '
                ':local t [/interface get $i type]; '
                ':local m [/interface monitor-traffic $i once as-value]; '
                ':put ("IF=" . $n . "|TYPE=" . $t . "|RX=" . ($m->"rx-bits-per-second") . "|TX=" . ($m->"tx-bits-per-second")) '
                '}'
            )
            _, raw_out, _ = _exec_ssh_cmd(ssh, cmd, timeout=18)
        elif mode == "portas":
            cmd = (
                ':put "===SEC:IF==="; /interface print without-paging; '
                ':put "===SEC:ETH==="; /interface ethernet print detail without-paging; '
                ':put "===SEC:SVC==="; /ip service print without-paging'
            )
            _, raw_out, _ = _exec_ssh_cmd(ssh, cmd, timeout=15)
        elif mode in ("sfp", "gbic"):
            cmd = (
                ':put "===SEC:SFP==="; '
                ':foreach i in=[/interface ethernet find where default-name~"sfp|combo|qsfp" or name~"sfp|combo|qsfp"] do={ '
                ':put "---IF---"; /interface ethernet monitor $i once '
                '}; '
                ':put "===SEC:TRAF==="; '
                ':foreach i in=[/interface find where default-name~"sfp|combo|qsfp" or name~"sfp|combo|qsfp"] do={ '
                ':local n [/interface get $i name]; '
                ':local m [/interface monitor-traffic $i once as-value]; '
                ':put ("IF=" . $n . "|RX=" . ($m->"rx-bits-per-second") . "|TX=" . ($m->"tx-bits-per-second")) '
                '}'
            )
            _, raw_out, _ = _exec_ssh_cmd(ssh, cmd, timeout=18)
        else:
            return False, {"error": "Modo inválido"}

        sections: dict[str, list[str]] = {}
        cur = "NONE"
        for line in raw_out.splitlines():
            m = re.match(r"^===SEC:([A-Z]+)===$", line.strip())
            if m:
                cur = m.group(1)
                sections[cur] = []
            else:
                sections.setdefault(cur, []).append(line)

        return True, {k: "\n".join(v) for k, v in sections.items()}
    except Exception as e:
        return False, {"error": str(e)}
    finally:
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass


async def _run_special_inspection(dev: dict, mode: str, client_tag: str = "telegram-bot") -> str:
    if not dev.get("ssh_enabled"):
        return f"❌ O acesso SSH está desabilitado no cadastro de <b>{html.escape(dev['name'])}</b>."

    password_plain = decrypt_secret(dev["ssh_password"])
    if not dev.get("ssh_username") or not password_plain:
        return f"❌ Credenciais SSH não configuradas para <b>{html.escape(dev['name'])}</b>."

    t0 = time.monotonic()
    async with SSH_SEMAPHORE:
        loop = asyncio.get_running_loop()
        ok, data = await loop.run_in_executor(
            None,
            _inspect_device_special_sync,
            dev["ip"],
            dev["ssh_port"],
            dev["ssh_username"],
            password_plain,
            dev.get("ros_version") or "auto",
            mode,
        )
    duration_ms = int((time.monotonic() - t0) * 1000)

    # Record in command_logs for auditing
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO command_logs (
                device_id, device_name, device_ip, action_key, command_executed,
                status, output_preview, duration_ms, client_ip, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
            """,
            (
                dev["id"],
                dev["name"],
                dev["ip"],
                f"tg_{mode}",
                f"[Telegram Bot] /{_device_command_slug(dev['name'])} {mode}",
                "SUCCESS" if ok else "ERROR",
                str(data.get("error") if not ok else f"Telegram {mode} inspection OK")[:500],
                duration_ms,
                client_tag,
            ),
        )
        prune_command_logs(c, 200)
        conn.commit()
    finally:
        conn.close()

    if not ok:
        return f"❌ <b>Erro SSH em {html.escape(dev['name'])}:</b> {html.escape(data.get('error', 'Falha desconhecida'))}"

    ver_lbl = dev.get("ros_version_detail") or (dev.get("ros_version") or "").upper()

    if mode == "links":
        routes = _parse_ros_detail_blocks(data.get("ROUTES", ""))
        netwatches = _parse_ros_detail_blocks(data.get("NW", ""))
        traf_map = {}
        for line in (data.get("TRAF", "") or "").splitlines():
            if line.startswith("IF="):
                parts = dict(item.split("=", 1) for item in line.split("|") if "=" in item)
                if_name = parts.get("IF", "").strip()
                if if_name:
                    traf_map[if_name] = (parts.get("RX", "0"), parts.get("TX", "0"))

        def_routes = sorted(
            [r for r in routes if r.get("dst-address") == "0.0.0.0/0"],
            key=lambda x: int(x.get("distance") or 1) if str(x.get("distance") or "1").isdigit() else 99,
        )
        mon_routes = [
            r for r in routes
            if r.get("dst-address", "").endswith("/32")
            and not ("D" in r.get("_flags", "") and "C" in r.get("_flags", ""))
        ]

        lines = [
            f"🛡️ <b>Status dos Links & Failover — {html.escape(dev['name'])}</b>",
            f"🌐 IP: <code>{html.escape(dev['ip'])}</code> • RouterOS <code>{html.escape(ver_lbl)}</code>",
            "",
            "<b>1️⃣ Rotas Padrão (Links WAN):</b>",
        ]
        if def_routes:
            for r in def_routes:
                flags = r.get("_flags", "")
                active = "A" in flags
                disabled = "X" in flags or r.get("disabled") == "yes"
                gw = r.get("gateway", "-")
                dist = r.get("distance", "1")
                comm = r.get("comment", "")
                if disabled:
                    icon = "🔴 INATIVA (DISABLED)"
                elif active:
                    icon = "🟢 ATIVA (EM USO)"
                else:
                    icon = "🔵 STANDBY (BACKUP)"
                role_lbl = f"<b>[{html.escape(comm)}]</b> " if comm else ""
                traf_str = ""
                if gw in traf_map:
                    rx, tx = traf_map[gw]
                    traf_str = f"\n   📊 Consumo agora: 📥 <b>{_fmt_bps(rx)}</b> | 📤 <b>{_fmt_bps(tx)}</b>"
                lines.append(
                    f"• {icon} {role_lbl}gw=<code>{html.escape(gw)}</code> (dist={html.escape(str(dist))}){traf_str}"
                )
        else:
            lines.append("• Nenhuma rota 0.0.0.0/0 encontrada.")

        lines.append("\n<b>2️⃣ Netwatch (/tool netwatch):</b>")
        if netwatches:
            for nw in netwatches:
                flags = nw.get("_flags", "")
                disabled = "X" in flags or nw.get("disabled") == "yes"
                st = (nw.get("status") or "unknown").upper()
                host = nw.get("host", "-")
                comm = nw.get("comment") or host
                interval = nw.get("interval", "-")
                if disabled:
                    st_icon = "⚪ PAUSADO"
                elif st == "UP":
                    st_icon = "🟢 UP"
                elif st == "DOWN":
                    st_icon = "🔴 DOWN"
                else:
                    st_icon = f"🟡 {st}"
                lines.append(
                    f"• <b>{html.escape(comm)}:</b> {st_icon} — ping <code>{html.escape(host)}</code> (a cada {html.escape(interval)})"
                )
        else:
            lines.append("• Nenhuma regra cadastrada no /tool netwatch.")

        if mon_routes:
            lines.append("\n<b>3️⃣ Rotas de Monitoramento (/32):</b>")
            for mr in mon_routes[:6]:
                flags = mr.get("_flags", "")
                is_bh = "b" in flags.lower() or "blackhole" in mr or mr.get("type") == "blackhole"
                gw = "BLACKHOLE" if is_bh else mr.get("gateway", "-")
                dst = mr.get("dst-address", "-")
                dist = mr.get("distance", "-")
                comm = mr.get("comment", "")
                lines.append(
                    f"• <code>{html.escape(dst)}</code> ➔ <code>{html.escape(gw)}</code> (dist={html.escape(str(dist))}) {html.escape(comm)}"
                )

        # Also show any running WAN/PPPoE/Ethernet interfaces with traffic if not matched by gateway name
        active_traf = []
        for if_name, (rx, tx) in traf_map.items():
            if if_name == "lo":
                continue
            try:
                total_bps = float(rx or 0) + float(tx or 0)
            except ValueError:
                total_bps = 0
            active_traf.append((total_bps, if_name, rx, tx))
        active_traf.sort(reverse=True)
        if active_traf:
            lines.append("\n<b>4️⃣ Consumo Instantâneo nas Interfaces Ativas:</b>")
            for _, if_name, rx, tx in active_traf[:8]:
                lines.append(
                    f"• <code>{html.escape(if_name)}</code>: 📥 <b>{_fmt_bps(rx)}</b> | 📤 <b>{_fmt_bps(tx)}</b>"
                )

        lines.append(f"\n⏱ <i>Consulta SSH concluída em {duration_ms} ms</i>")
        return "\n".join(lines)

    if mode == "consumo":
        res_text = data.get("RES", "")
        cpu_m = re.search(r"cpu-load:\s*(\d+)%", res_text)
        up_m = re.search(r"uptime:\s*([^\r\n]+)", res_text)
        cpu_str = f"{cpu_m.group(1)}%" if cpu_m else "-"
        up_str = up_m.group(1).strip() if up_m else "-"

        rows = []
        for line in (data.get("TRAF", "") or "").splitlines():
            if line.startswith("IF="):
                parts = dict(item.split("=", 1) for item in line.split("|") if "=" in item)
                if_name = parts.get("IF", "").strip()
                if not if_name or if_name == "lo" or if_name.startswith("<pppoe-"):
                    continue
                rx = parts.get("RX", "0")
                tx = parts.get("TX", "0")
                try:
                    tot = float(rx or 0) + float(tx or 0)
                except ValueError:
                    tot = 0.0
                if tot > 50_000:
                    rows.append((tot, if_name, rx, tx))

        rows.sort(reverse=True)
        lines = [
            "📊 <b>Consumo em Tempo Real</b>",
            f"CPU: <b>{html.escape(cpu_str)}</b> • Uptime: <code>{html.escape(_fmt_uptime_ptbr(up_str))}</code>",
            "",
        ]
        if rows:
            for _, if_name, rx, tx in rows[:15]:
                lines.append(
                    f"• <b>{html.escape(if_name)}:</b> 📥 {_fmt_bps(rx)} | 📤 {_fmt_bps(tx)}"
                )
        else:
            lines.append("Nenhum tráfego relevante nas interfaces principais no momento.")
        return "\n".join(lines)

    if mode == "portas":
        eth_items = _parse_ros_detail_blocks(data.get("ETH", ""))
        if_text = (data.get("IF", "") or "").strip()
        svc_text = (data.get("SVC", "") or "").strip()

        lines = [
            f"🔌 <b>Portas e Interfaces — {html.escape(dev['name'])}</b>",
            f"🌐 IP: <code>{html.escape(dev['ip'])}</code> • RouterOS <code>{html.escape(ver_lbl)}</code>",
            "",
            "<b>Estado das Portas Ethernet:</b>",
        ]
        if eth_items:
            for e in eth_items:
                orig_name = e.get("default-name", "")
                name = e.get("name") or orig_name or "-"
                flags = e.get("_flags", "")
                disabled = "X" in flags or e.get("disabled") == "yes"
                running = "R" in flags
                slave = "S" in flags
                st_lbl = "🔴 DESATIVADA" if disabled else ("🟢 CONECTADA (R)" if running else "⚪ SEM CABO / DOWN")
                slave_lbl = " [Bridge/Slave]" if slave else ""
                orig_lbl = f" ({orig_name})" if orig_name and orig_name != name else ""
                lines.append(f"• <code>{html.escape(name)}</code>{html.escape(orig_lbl)}: {st_lbl}{slave_lbl}")
        elif if_text:
            lines.append(_safe_pre(if_text, 1600))

        if svc_text:
            lines.append("\n<b>Portas de Serviço (/ip service):</b>")
            lines.append(_safe_pre(svc_text, 1200))

        lines.append(f"⏱ <i>Consulta SSH concluída em {duration_ms} ms</i>")
        return "\n".join(lines)

    if mode in ("sfp", "gbic"):
        sfp_text = data.get("SFP", "")
        traf_map = {}
        for line in (data.get("TRAF", "") or "").splitlines():
            if line.startswith("IF="):
                parts = dict(item.split("=", 1) for item in line.split("|") if "=" in item)
                if_name = parts.get("IF", "").strip()
                if if_name:
                    traf_map[if_name] = (parts.get("RX", "0"), parts.get("TX", "0"))

        mon_items = _parse_ethernet_monitor_blocks(sfp_text)
        lines = [
            "💡 <b>Sinal Óptico & Portas GBIC/SFP</b>\n",
        ]

        if not mon_items:
            lines.append("Nenhuma porta SFP/GBIC detectada com comando de monitoramento.")
            if sfp_text.strip():
                lines.append(_safe_pre(sfp_text, 1500))
        else:
            for item in mon_items:
                if_name = item.get("name", "Porta")
                status = item.get("status", "unknown")
                rate = item.get("rate", "")
                module_present = item.get("sfp-module-present", "").lower()
                sfp_type = item.get("sfp-type", "")
                vendor = item.get("sfp-vendor-name", "")
                part_no = item.get("sfp-vendor-part-number", "")
                wavelength = item.get("sfp-wavelength", "")
                rx_pwr = item.get("sfp-rx-power", "")
                tx_pwr = item.get("sfp-tx-power", "")
                temp = item.get("sfp-temperature", "")
                voltage = item.get("sfp-supply-voltage", "")
                current_bias = item.get("sfp-tx-bias-current", "")
                rx_loss = item.get("sfp-rx-lose", "").lower()

                status_badge = "🟢 LINK OK" if status == "link-ok" else "🔴 SEM LINK"
                if rate:
                    status_badge += f" ({rate})"

                lines.append(f"• <b>Porta:</b> <code>{html.escape(if_name)}</code> — {status_badge}")

                if module_present == "no":
                    lines.append("   <i>Módulo SFP/GBIC não conectado na porta.</i>\n")
                    continue

                # Optical RX Signal evaluation
                rx_badge = ""
                if rx_pwr:
                    try:
                        clean_rx = re.sub(r"[^\d.-]", "", rx_pwr)
                        rx_val = float(clean_rx)
                        if rx_val >= -15.0:
                            rx_badge = " (Excelente)"
                        elif -22.0 <= rx_val < -15.0:
                            rx_badge = " (Normal)"
                        elif -25.0 <= rx_val < -22.0:
                            rx_badge = " 🟡 (Atenção)"
                        else:
                            rx_badge = " 🔴 (Crítico)"
                    except Exception:
                        pass
                elif rx_loss == "yes":
                    rx_badge = " 🔴 (SEM SINAL / LOSS)"

                mod_info = []
                if vendor:
                    mod_info.append(f"Fab: {vendor}")
                if part_no:
                    mod_info.append(f"Modelo: {part_no}")
                if wavelength:
                    mod_info.append(f"λ {wavelength}")

                if mod_info:
                    lines.append(f"   GBIC: {html.escape(' | '.join(mod_info))}")

                pwr_details = []
                if rx_pwr:
                    pwr_details.append(f"Rx Power: <code>{html.escape(rx_pwr)}</code>{rx_badge}")
                elif rx_loss == "yes":
                    pwr_details.append("Rx Power: <code>SEM SINAL</code> 🔴")
                else:
                    pwr_details.append("Rx Power: <code>--</code>")

                if tx_pwr:
                    pwr_details.append(f"Tx Power: <code>{html.escape(tx_pwr)}</code>")

                lines.append("   " + " | ".join(pwr_details))

                diag_info = []
                if temp:
                    diag_info.append(f"Temp: {html.escape(temp)}")
                if voltage:
                    diag_info.append(f"Tensão: {html.escape(voltage)}")
                if current_bias:
                    diag_info.append(f"Corrente: {html.escape(current_bias)}")
                if diag_info:
                    lines.append("   " + " • ".join(diag_info))

                if if_name in traf_map:
                    rx_t, tx_t = traf_map[if_name]
                    lines.append(f"   Consumo: 📥 {_fmt_bps(rx_t)} | 📤 {_fmt_bps(tx_t)}")

                lines.append("")

        return "\n".join(lines).strip()

    return "❌ Modo não suportado."


async def _inspect_pppoe_login(dev: dict, login_user: str) -> str:
    clean_user = re.sub(r'["\';\s]', "", (login_user or "").strip())
    if not clean_user:
        return "🔍 <b>Uso:</b> <code>/login &lt;nome_pppoe&gt;</code>\nExemplo: <code>/login nidairma</code>"

    if not dev.get("ssh_enabled"):
        return f"❌ O acesso SSH está desabilitado para <b>{html.escape(dev['name'])}</b>."

    password_plain = decrypt_secret(dev["ssh_password"])
    if not dev.get("ssh_username") or not password_plain:
        return f"❌ Credenciais SSH não configuradas para <b>{html.escape(dev['name'])}</b>."

    async with SSH_SEMAPHORE:
        loop = asyncio.get_running_loop()
        def _query_login_sync():
            ssh = _connect_ssh(dev["ip"], dev["ssh_port"] or 22, dev["ssh_username"], password_plain, timeout=8)
            try:
                cmd = (
                    ':local p [/ppp active find where name="' + clean_user + '"]; '
                    ':if ([:len $p] > 0) do={'
                    '  :local a [/ppp active get $p address]; '
                    '  :local up [/ppp active get $p uptime]; '
                    '  :local mac [/ppp active get $p caller-id]; '
                    '  :local ifn ("<pppoe-" . "' + clean_user + '" . ">"); '
                    '  :local ifi [/interface find name=$ifn]; '
                    '  :local rxb 0; :local txb 0; :local curRx 0; :local curTx 0; '
                    '  :if ([:len $ifi] > 0) do={'
                    '    :set rxb [/interface get $ifi rx-byte]; '
                    '    :set txb [/interface get $ifi tx-byte]; '
                    '    :local m [/interface monitor-traffic $ifi once as-value]; '
                    '    :set curRx ($m->"rx-bits-per-second"); '
                    '    :set curTx ($m->"tx-bits-per-second"); '
                    '  }; '
                    '  :local ipv6pd ""; '
                    '  :local b [/ipv6 dhcp-server binding find where server=$ifn]; '
                    '  :if ([:len $b] > 0) do={ :set ipv6pd [/ipv6 dhcp-server binding get $b address] }; '
                    '  :local ipv6wan ""; '
                    '  :local pu [/ipv6 pool used find where info="' + clean_user + '"]; '
                    '  :if ([:len $pu] > 0) do={ :set ipv6wan [/ipv6 pool used get $pu prefix] }; '
                    '  :put ("OK|IPV4=" . $a . "|UP=" . $up . "|MAC=" . $mac . "|RXB=" . $rxb . "|TXB=" . $txb . "|CURRX=" . $curRx . "|CURTX=" . $curTx . "|PD=" . $ipv6pd . "|WAN6=" . $ipv6wan); '
                    '} else={'
                    '  :local s [/ppp secret find where name="' + clean_user + '"]; '
                    '  :if ([:len $s] > 0) do={ :put "OFFLINE" } else={ :put "NOTFOUND" }; '
                    '}'
                )
                _, out, _ = _exec_ssh_cmd(ssh, cmd, timeout=8)
                return out.strip()
            finally:
                ssh.close()

        try:
            raw_res = await loop.run_in_executor(None, _query_login_sync)
        except Exception as e:
            return f"❌ <b>Erro ao consultar login:</b> {html.escape(str(e))}"

    if "NOTFOUND" in raw_res:
        return f"❌ Login PPPoE <code>{html.escape(clean_user)}</code> não encontrado no MikroTik."

    if "OFFLINE" in raw_res:
        return (
            f"👤 <b>Login PPPoE:</b> <code>{html.escape(clean_user)}</code>\n\n"
            f"• <b>Status:</b> ⚪ OFFLINE (Desconectado)\n"
            f"• <i>O usuário existe no cadastro (/ppp secret), mas não está discado no momento.</i>"
        )

    ok_line = next((l for l in raw_res.splitlines() if l.startswith("OK|")), "")
    if not ok_line:
        return f"⚠️ Resposta inesperada ao consultar <code>{html.escape(clean_user)}</code>:\n{_safe_pre(raw_res)}"

    parts = dict(item.split("=", 1) for item in ok_line[3:].split("|") if "=" in item)
    ipv4 = parts.get("IPV4", "-")
    uptime = parts.get("UP", "-")
    mac = parts.get("MAC", "-")
    rxb = parts.get("RXB", "0")
    txb = parts.get("TXB", "0")
    cur_rx = parts.get("CURRX", "0")
    cur_tx = parts.get("CURTX", "0")
    pd = parts.get("PD", "")
    wan6 = parts.get("WAN6", "")

    is_blocked = ipv4.startswith("10.24.")
    status_str = "🔴 CONECTADO (BLOQUEADO)" if is_blocked else "🟢 CONECTADO (ONLINE)"

    dl_bytes = _fmt_bytes(txb)
    ul_bytes = _fmt_bytes(rxb)
    try:
        tot_bytes = float(rxb or 0) + float(txb or 0)
    except ValueError:
        tot_bytes = 0.0
    total_str = _fmt_bytes(tot_bytes)

    lines = [
        f"👤 <b>Login PPPoE:</b> <code>{html.escape(clean_user)}</code>",
        f"• <b>Status:</b> {status_str}",
        f"• <b>IPv4:</b> <code>{html.escape(ipv4)}</code>",
    ]

    if pd:
        lines.append(f"• <b>IPv6 Delegado (LAN):</b> <code>{html.escape(pd)}</code>")
    if wan6:
        lines.append(f"• <b>IPv6 WAN:</b> <code>{html.escape(wan6)}</code>")
    if not pd and not wan6:
        lines.append("• <b>IPv6:</b> <i>Não atribuído</i>")

    lines.append(f"• <b>Tempo Conectado:</b> <code>{html.escape(_fmt_uptime_ptbr(uptime))}</code>")
    lines.append(f"• <b>MAC / Caller-ID:</b> <code>{html.escape(mac)}</code>\n")
    lines.append("📊 <b>Consumo na Sessão Atual:</b>")
    lines.append(f"• <b>Download:</b> <code>{dl_bytes}</code>")
    lines.append(f"• <b>Upload:</b> <code>{ul_bytes}</code>")
    lines.append(f"• <b>Total Trafegado:</b> <b>{total_str}</b>")

    try:
        cur_tot = float(cur_rx or 0) + float(cur_tx or 0)
    except ValueError:
        cur_tot = 0.0
    if cur_tot > 0:
        lines.append(f"• <b>Velocidade Agora:</b> 📥 {_fmt_bps(cur_tx)} | 📤 {_fmt_bps(cur_rx)}")

    return "\n".join(lines)


async def _execute_bot_subcommand(dev: dict, subcmd: str, arg: str = "") -> str:
    """Routes a device subcommand to either a rich inspection, quick action, or custom CLI."""
    sub = (subcmd or "").strip().lower()
    arg_clean = (arg or "").strip()

    # 1. Rich inspections (Login, GBIC/SFP, Consumo & Portas)
    if sub in ("login", "pppoe_login", "user", "usuario"):
        return await _inspect_pppoe_login(dev, arg_clean)

    if sub in ("gbic", "sfp", "otico", "fibra", "potencia_gbic", "sinal_gbic"):
        return await _run_special_inspection(dev, "gbic")

    if sub in ("consumo", "trafego", "traffic", "banda", "velocidade", "bps"):
        return await _run_special_inspection(dev, "consumo")

    if sub in ("portas", "porta", "ethernet", "ether", "interfaces"):
        return await _run_special_inspection(dev, "portas")

    if sub in ("clientes", "pppoe", "ipoe", "usuarios"):
        async with SSH_SEMAPHORE:
            loop = asyncio.get_running_loop()
            def _get_clients_sync():
                pwd = decrypt_secret(dev["ssh_password"])
                ssh = _connect_ssh(dev["ip"], dev["ssh_port"] or 22, dev["ssh_username"], pwd, timeout=8)
                try:
                    cmd = (
                        ':put ("TOTAL=" . [/ppp active print count-only]); '
                        ':foreach i in=[/ppp active find] do={ '
                        ':local a [/ppp active get $i address]; '
                        'if ([:pick $a 0 5] = "10.24") do={ '
                        ':put ("BLK=" . [/ppp active get $i name] . "|" . $a) '
                        '} }'
                    )
                    _, out, _ = _exec_ssh_cmd(ssh, cmd, timeout=8)
                    total_online = "0"
                    blocked_list = []
                    for line in out.splitlines():
                        line = line.strip()
                        if line.startswith("TOTAL="):
                            total_online = line.split("=", 1)[1].strip()
                        elif line.startswith("BLK="):
                            raw_blk = line.split("=", 1)[1].strip()
                            if "|" in raw_blk:
                                n_val, ip_val = raw_blk.split("|", 1)
                                blocked_list.append((n_val.strip(), ip_val.strip()))
                            elif raw_blk:
                                blocked_list.append((raw_blk, ""))
                    return total_online, blocked_list
                finally:
                    ssh.close()
            try:
                total_online, blocked_list = await loop.run_in_executor(None, _get_clients_sync)
                lines = [
                    "👥 <b>Clientes Conectados</b>\n",
                    f"• <b>PPPoE Ativos:</b> <code>{total_online}</code> clientes",
                    f"• <b>Bloqueados Online:</b> <code>{len(blocked_list)}</code> clientes",
                ]
                if blocked_list:
                    for b_name, b_ip in blocked_list:
                        ip_txt = f" ({b_ip})" if b_ip else ""
                        lines.append(f"  🔴 <code>{html.escape(b_name)}</code>{ip_txt}")
                return "\n".join(lines)
            except Exception as e:
                return f"❌ <b>Erro ao consultar clientes:</b> {html.escape(str(e))}"

    if sub in ("pingnet", "ping_internet", "internet"):
        async with SSH_SEMAPHORE:
            loop = asyncio.get_running_loop()
            def _ping_sync():
                pwd = decrypt_secret(dev["ssh_password"])
                ssh = _connect_ssh(dev["ip"], dev["ssh_port"] or 22, dev["ssh_username"], pwd, timeout=8)
                try:
                    _, out1, _ = _exec_ssh_cmd(ssh, "/ping 8.8.8.8 count=4", timeout=8)
                    _, out2, _ = _exec_ssh_cmd(ssh, "/ping 1.1.1.1 count=4", timeout=8)
                    return out1.strip(), out2.strip()
                finally:
                    ssh.close()
            try:
                p1, p2 = await loop.run_in_executor(None, _ping_sync)
                return (
                    f"🌐 <b>Teste de Conectividade com a Internet — {html.escape(dev['name'])}</b>\n\n"
                    f"<b>Ping 8.8.8.8 (Google):</b>\n{_safe_pre(p1)}\n\n"
                    f"<b>Ping 1.1.1.1 (Cloudflare):</b>\n{_safe_pre(p2)}"
                )
            except Exception as e:
                return f"❌ <b>Erro no ping para a internet:</b> {html.escape(str(e))}"

    if sub in ("backup", "bkp"):
        ok, msg = await run_backup_for_device(dev, manual=True)
        if ok:
            return f"✅ <b>Backup Realizado com Sucesso!</b>\n{html.escape(dev['name'])}: {html.escape(msg)}"
        return f"❌ <b>Falha ao realizar backup:</b>\n{html.escape(dev['name'])}: {html.escape(msg)}"

    if sub == "olt_search":
        if not _device_has_olt(dev):
            return "❌ Este equipamento não possui OLT vinculada."
        return (
            "🔍 <b>Consulta de ONU na OLT Cianet</b>\n\n"
            "Envie o comando:\n"
            "<code>/onu &lt;MAC ou Serial&gt;</code>\n\n"
            "Exemplo:\n"
            "<code>/onu FHTTFE282DC4</code> ou <code>/onu ITBS0ACD111A</code>"
        )

    if sub == "olt_unauth":
        if not _device_has_olt(dev):
            return "❌ Este equipamento não possui OLT vinculada."
        from app.olt_cianet import get_unauthorized_onts_async
        unauth = await get_unauthorized_onts_async()
        if not unauth:
            return "✅ <b>OLT Cianet:</b> Nenhuma ONU aguardando autorização no momento (autofind vazio)."
        lines = ["🆕 <b>ONUs Não Autorizadas Encontradas:</b>\n"]
        for u in unauth:
            p_num = u.get("port", 1)
            sn_val = u.get("sn", "")
            lines.append(f"• <b>Porta PON {p_num}:</b> <code>{html.escape(sn_val)}</code>")
        lines.append("\nPara autorizar envie: <code>/autorizar &lt;porta&gt; &lt;serial&gt;</code>")
        return "\n".join(lines)

    # 2. Map standardized subcommands to QUICK_ACTIONS
    alias_map = {
        "ips": "ip_addresses",
        "ip": "ip_addresses",
        "enderecos": "ip_addresses",
        "rotas": "routes",
        "rota": "routes",
        "routes": "routes",
        "route": "routes",
        "recursos": "system_info",
        "status": "system_info",
        "info": "system_info",
        "saude": "system_info",
        "cpu": "system_info",
        "hardware": "system_info",
        "logs": "recent_logs",
        "log": "recent_logs",
        "firewall": "firewall_nat",
        "nat": "firewall_nat",
        "filter": "firewall_filter",
        "dhcp": "dhcp_leases",
        "leases": "dhcp_leases",
        "arp": "arp_table",
        "bgp": "bgp_status",
        "snmp": "snmp_config",
        "servicos": "ip_services",
        "services": "ip_services",
    }

    if sub in alias_map:
        action_key = alias_map[sub]
        res = await execute_device_command(dev, action_key, "", "", client_ip="telegram-bot")
        if not res.get("ok"):
            return f"❌ <b>{html.escape(dev['name'])}:</b> {html.escape(res.get('error') or res.get('output') or 'Erro')}"
        out = (res.get("output") or "").strip()
        if action_key == "recent_logs":
            log_lines = out.splitlines()
            if len(log_lines) > 35:
                out = "\n".join(log_lines[-35:])
        return (
            f"🖥 <b>{html.escape(dev['name'])} ({html.escape(dev['ip'])}) — {html.escape(sub.upper())}</b>\n"
            f"<code>{html.escape(res.get('command') or '')}</code>\n"
            f"{_safe_pre(out)}\n"
            f"⏱ <i>{res.get('duration_ms', 0)} ms</i>"
        )

    if sub == "ping":
        target = arg_clean or "8.8.8.8"
        res = await execute_device_command(dev, "tool_ping", target, "", client_ip="telegram-bot")
        if not res.get("ok"):
            return f"❌ <b>{html.escape(dev['name'])}:</b> {html.escape(res.get('error') or 'Erro no ping')}"
        return (
            f"📡 <b>Ping a partir de {html.escape(dev['name'])} para {html.escape(target)}</b>\n"
            f"{_safe_pre(res.get('output') or '')}"
        )

    if sub in ("traceroute", "trace"):
        target = arg_clean or "1.1.1.1"
        res = await execute_device_command(dev, "tool_traceroute", target, "", client_ip="telegram-bot")
        if not res.get("ok"):
            return f"❌ <b>{html.escape(dev['name'])}:</b> {html.escape(res.get('error') or 'Erro no traceroute')}"
        return (
            f"🧭 <b>Traceroute a partir de {html.escape(dev['name'])} para {html.escape(target)}</b>\n"
            f"{_safe_pre(res.get('output') or '')}"
        )

    if sub in ("cmd", "exec") and arg_clean:
        res = await execute_device_command(dev, "custom", "", arg_clean, client_ip="telegram-bot")
        if not res.get("ok"):
            return f"❌ <b>{html.escape(dev['name'])}:</b> {html.escape(res.get('error') or 'Comando recusado')}"
        return (
            f"⚡ <b>{html.escape(dev['name'])} — Comando Customizado</b>\n"
            f"<code>{html.escape(arg_clean)}</code>\n"
            f"{_safe_pre(res.get('output') or '')}"
        )

    # Check if the user passed a raw RouterOS command directly (e.g. `/balaio /ip route print`)
    full_raw = f"{subcmd} {arg_clean}".strip()
    if full_raw.startswith("/"):
        res = await execute_device_command(dev, "custom", "", full_raw, client_ip="telegram-bot")
        if not res.get("ok"):
            return f"❌ <b>{html.escape(dev['name'])}:</b> {html.escape(res.get('error') or 'Comando recusado')}"
        return (
            f"⚡ <b>{html.escape(dev['name'])} — Comando RouterOS</b>\n"
            f"<code>{html.escape(full_raw)}</code>\n"
            f"{_safe_pre(res.get('output') or '')}"
        )

    slug = _device_command_slug(dev["name"])
    if dev.get("device_type") == "provedor":
        return (
            f"❓ Comando <code>{html.escape(sub)}</code> não reconhecido para <b>{html.escape(dev['name'])}</b>.\n\n"
            f"<b>Comandos disponíveis:</b>\n"
            f"• <code>/{slug} clientes</code> — Total de clientes e bloqueados\n"
            f"• <code>/{slug} login &lt;nome&gt;</code> — Resumo da conexão do cliente PPPoE\n"
            f"• <code>/{slug} gbic</code> — Níveis de sinal das portas GBIC/SFP\n"
            f"• <code>/{slug} consumo</code> — Consumo de banda em tempo real\n"
            f"• <code>/{slug} pingnet</code> — Teste de latência com a internet\n"
            f"• <code>/{slug} recursos</code> — CPU, memória e uptime\n"
            f"• <code>/{slug} logs</code> — Últimos eventos do log"
        )

    return (
        f"❓ Comando <code>{html.escape(sub)}</code> não reconhecido para <b>{html.escape(dev['name'])}</b>.\n\n"
        f"<b>Comandos disponíveis:</b>\n"
        f"• <code>/{slug} ips</code> — Endereços IP configurados\n"
        f"• <code>/{slug} rotas</code> — Tabela de rotas ativas\n"
        f"• <code>/{slug} consumo</code> — Consumo em tempo real (Mbps/Kbps)\n"
        f"• <code>/{slug} portas</code> — Estado das portas Ethernet e serviços\n"
        f"• <code>/{slug} recursos</code> — CPU, memória, uptime e saúde\n"
        f"• <code>/{slug} logs</code> — Últimos eventos do log"
    )


def _format_device_card(dev: dict) -> str:
    st = dev.get("status") or "UP"
    icon = "🟢 ONLINE" if st == "UP" else "🔴 DOWN"
    ver = dev.get("ros_version_detail") or (dev.get("ros_version") or "-").upper()
    lat = f"{dev['latency_ms']:.1f} ms" if dev.get("latency_ms") is not None else "-"
    cpu = f"{dev['cpu_load']}%" if dev.get("cpu_load") is not None else "-"
    mem = f"{dev['memory_used_pct']:.0f}%" if dev.get("memory_used_pct") is not None else "-"
    up = dev.get("uptime_str") or "-"
    slug = _device_command_slug(dev["name"])

    if dev.get("device_type") == "provedor":
        has_olt = _device_has_olt(dev)
        olt_hints = ""
        if has_olt:
            olt_hints = (
                f"• <code>/onu &lt;MAC ou Serial&gt;</code> — Consulta sinal e status da ONU\n"
                f"• <code>/onus_novas</code> — ONUs em autofind\n"
            )
        return (
            f"🖥 <b>{html.escape(dev['name'])}</b> — {icon}\n"
            f"🌐 IP: <code>{html.escape(dev['ip'])}:{dev.get('ssh_port') or 2250}</code> • RouterOS: <code>{html.escape(ver)}</code>\n"
            f"📶 Latência: <b>{lat}</b> • 💻 CPU: <b>{cpu}</b> • 🧠 Mem: <b>{mem}</b>\n"
            f"⏱ Uptime: <code>{html.escape(_fmt_uptime_ptbr(up))}</code>\n\n"
            f"<b>Toque nos botões abaixo ou envie pelo chat:</b>\n"
            f"• <code>/{slug} clientes</code> — Clientes ativos e bloqueados\n"
            f"• <code>/{slug} login &lt;nome&gt;</code> — Resumo da conexão do cliente PPPoE\n"
            f"• <code>/{slug} gbic</code> — Níveis de sinal das portas GBIC/SFP\n"
            f"• <code>/{slug} consumo</code> — Consumo de banda em tempo real\n"
            f"• <code>/{slug} pingnet</code> — Teste de latência com a internet\n"
            f"• <code>/{slug} recursos</code> — CPU, memória e uptime\n"
            f"• <code>/{slug} logs</code> — Últimos eventos do log\n"
            f"{olt_hints}"
        )

    return (
        f"🖥 <b>{html.escape(dev['name'])}</b> — {icon}\n"
        f"🌐 IP: <code>{html.escape(dev['ip'])}:{dev.get('ssh_port') or 2250}</code> • RouterOS: <code>{html.escape(ver)}</code>\n"
        f"📶 Latência: <b>{lat}</b> • 💻 CPU: <b>{cpu}</b> • 🧠 Mem: <b>{mem}</b>\n"
        f"⏱ Uptime: <code>{html.escape(_fmt_uptime_ptbr(up))}</code>\n\n"
        f"<b>Comandos rápidos pelo chat ou botões abaixo:</b>\n"
        f"• <code>/{slug} ips</code> — Endereços IP das interfaces\n"
        f"• <code>/{slug} rotas</code> — Rotas ativas\n"
        f"• <code>/{slug} consumo</code> — Consumo de banda agora\n"
        f"• <code>/{slug} portas</code> — Portas físicas e serviços\n"
        f"• <code>/{slug} recursos</code> — CPU, memória, uptime e saúde\n"
        f"• <code>/{slug} logs</code> — Últimos logs da RB"
    )


def _get_authorized_bots_and_devices() -> list[dict]:
    """
    Returns all active bot configurations from `settings` and `telegram_destinations`,
    along with the authorized chat_ids and accessible devices for each token.
    """
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE active=1 ORDER BY name COLLATE NOCASE")
        all_devs = [dict(r) for r in c.fetchall()]
        c.execute("SELECT * FROM telegram_destinations")
        dest_rows = [dict(r) for r in c.fetchall()]
    finally:
        conn.close()

    default_token = (get_setting("telegram_bot_token") or "").strip()
    default_chat = str(get_setting("telegram_chat_id") or "").strip()

    bots_by_token: dict[str, dict] = {}
    if default_token:
        bots_by_token[default_token] = {
            "token": default_token,
            "is_admin_bot": True,
            "chats": {default_chat: None} if default_chat else {},  # None -> access all devices
            "all_devices": all_devs,
        }

    for d in dest_rows:
        tok = (d.get("token") or "").strip() or default_token
        cid = str(d.get("chat_id") or "").strip()
        if not tok or not cid:
            continue
        if tok not in bots_by_token:
            bots_by_token[tok] = {
                "token": tok,
                "is_admin_bot": False,
                "chats": {},
                "all_devices": all_devs,
            }
        # If this chat_id is already the default admin chat, keep None (all devices)
        if cid not in bots_by_token[tok]["chats"]:
            bots_by_token[tok]["chats"][cid] = d["id"]

    return list(bots_by_token.values())


def _devices_for_chat(all_devs: list[dict], dest_scope_id: int | None) -> list[dict]:
    """
    Strictly filters devices belonging to the given Telegram destination:
    - dest_scope_id is None (Default Bot): only devices using 'Padrão do Sistema' (telegram_destination_id is None/0)
    - dest_scope_id is int (Destination Bot): only devices assigned to that specific telegram_destination_id
    """
    if dest_scope_id is None:
        return [d for d in all_devs if not d.get("telegram_destination_id")]
    return [d for d in all_devs if d.get("telegram_destination_id") == dest_scope_id]


def _match_device_and_subcommand(raw_cmd_token: str, rest_text: str, devices: list[dict]) -> tuple[dict | None, str, str]:
    """
    Matches `/equipamento comando arg` flexibly:
    - `/balaio links` -> (BALAIO, 'links', '')
    - `/bom_preco consumo` or `/bompreco consumo` -> (BOM PRECO, 'consumo', '')
    - `/bom preco consumo` -> (BOM PRECO, 'consumo', '')
    - `/cristal_cru links` or `/cristal cru via gnet links` -> (CRISTAL CRU via GNET, 'links', '')
    """
    cmd_slug = _normalize_slug(raw_cmd_token)
    cmd_compact = cmd_slug.replace("_", "")
    rest_clean = (rest_text or "").strip()

    # Build candidate index sorted by longest name first so specific names ('EDGAR PREDIO') match before prefix ('EDGAR')
    indexed = []
    for d in devices:
        full_slug = _normalize_slug(d["name"])
        short_slug = _device_command_slug(d["name"])
        indexed.append((len(full_slug), full_slug, short_slug, full_slug.replace("_", ""), short_slug.replace("_", ""), d))
    indexed.sort(key=lambda x: x[0], reverse=True)

    # 1. Exact match on command token (`/balaio`, `/bom_preco`, `/bompreco`, `/edgar_predio`)
    # Wait: if the user typed `/edgar predio links`, raw_cmd_token is `edgar` and rest_clean starts with `predio`!
    # So first check if `cmd_slug + "_" + rest_words` matches a multi-word device name!
    rest_words = rest_clean.split()
    for n_words in range(min(4, len(rest_words)), 0, -1):
        combined_slug = _normalize_slug(raw_cmd_token + " " + " ".join(rest_words[:n_words]))
        for _, full_slug, short_slug, _, _, d in indexed:
            if combined_slug in (full_slug, short_slug):
                remaining = " ".join(rest_words[n_words:]).strip()
                sub_parts = remaining.split(maxsplit=1)
                sub = sub_parts[0] if sub_parts else ""
                arg = sub_parts[1] if len(sub_parts) > 1 else ""
                return d, sub, arg

    # 2. Direct match on the slash command token itself
    for _, full_slug, short_slug, full_comp, short_comp, d in indexed:
        if cmd_slug in (full_slug, short_slug) or cmd_compact in (full_comp, short_comp):
            sub_parts = rest_clean.split(maxsplit=1)
            sub = sub_parts[0] if sub_parts else ""
            arg = sub_parts[1] if len(sub_parts) > 1 else ""
            return d, sub, arg

    # 3. Prefix match if unambiguous (e.g., `/mcd links` -> `MCD SANTA CRUZ`)
    for _, full_slug, short_slug, _, _, d in indexed:
        if len(cmd_slug) >= 3 and (full_slug.startswith(cmd_slug + "_") or short_slug.startswith(cmd_slug)):
            sub_parts = rest_clean.split(maxsplit=1)
            sub = sub_parts[0] if sub_parts else ""
            arg = sub_parts[1] if len(sub_parts) > 1 else ""
            return d, sub, arg

    return None, "", ""


async def _tg_api_post(session: aiohttp.ClientSession, token: str, method: str, payload: dict) -> dict:
    url = f"https://api.telegram.org/bot{token}/{method}"
    try:
        async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            return await resp.json()
    except Exception as e:
        print(f"[TelegramBot API Error] {method}: {e}")
        return {"ok": False}


async def _send_bot_reply(
    session: aiohttp.ClientSession,
    token: str,
    chat_id: str | int,
    text: str,
    reply_to_message_id: int | None = None,
    reply_markup: dict | None = None,
):
    payload: dict = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if reply_to_message_id:
        payload["reply_to_message_id"] = reply_to_message_id
    if reply_markup:
        payload["reply_markup"] = reply_markup
    await _tg_api_post(session, token, "sendMessage", payload)


def _build_help_message(devices: list[dict], dest_scope_id: int | None = None) -> str:
    dev_lines = []
    has_provider = any(d.get("device_type") == "provedor" for d in devices)
    has_olt = (dest_scope_id == 3) or any(_device_has_olt(d) for d in devices)

    for d in devices:
        slug = _device_command_slug(d["name"])
        st_icon = "🟢" if (d.get("status") or "UP") == "UP" else "🔴"
        ver = d.get("ros_version_detail") or (d.get("ros_version") or "").upper()
        ssh_tag = "" if d.get("ssh_enabled") else " <i>(SSH off)</i>"
        dev_lines.append(f"{st_icon} <code>/{slug}</code> — <b>{html.escape(d['name'])}</b> ({html.escape(ver)}){ssh_tag}")

    title_part = " & OLT" if has_olt else ""

    if has_provider:
        multidev_hint = ""
        if len(devices) > 1:
            slug_examples = " ou ".join(f"<code>/{_device_command_slug(d['name'])}</code>" for d in devices[:2])
            multidev_hint = (
                f"💡 <i>Como há mais de um equipamento neste bot, escolha primeiro o equipamento ({slug_examples}) "
                f"para abrir seu menu com botões exclusivos, ou envie o comando direto (o bot fará a triagem).</i>\n\n"
            )

        olt_section = ""
        if has_olt:
            olt_section = (
                "\n<b>📟 Comandos OLT GPON (Cianet):</b>\n"
                "• <code>/onu &lt;MAC ou Serial&gt;</code> — Consulta status e níveis de sinal óptico (RX/TX)\n"
                "• <code>/onus_novas</code> — Lista ONUs aguardando autorização (autofind)\n"
                "• <code>/autorizar &lt;porta&gt; &lt;serial&gt;</code> — Autoriza a ONU na porta informada\n"
                "• <code>/desautorizar &lt;porta&gt; &lt;ont_id&gt;</code> — Remove/desautoriza a ONU\n"
            )

        return (
            f"🤖 <b>Bot BKPProvider — Comandos Remotos Provedor{title_part}</b>\n\n"
            f"{multidev_hint}"
            "<b>📌 Comandos Disponíveis:</b>\n"
            "1️⃣ <code>/clientes</code> ou <code>/equipamento clientes</code> — Total de clientes e bloqueados\n"
            "2️⃣ <code>/login &lt;nome&gt;</code> ou <code>/equipamento login &lt;nome&gt;</code> — Resumo da conexão do cliente PPPoE\n"
            "3️⃣ <code>/gbic</code> ou <code>/equipamento gbic</code> — Sinal óptico das portas GBIC/SFP\n"
            "4️⃣ <code>/consumo</code> ou <code>/equipamento consumo</code> — Tráfego de banda em tempo real\n"
            "5️⃣ <code>/equipamento pingnet</code> — Teste de latência para a internet (8.8.8.8)\n"
            "6️⃣ <code>/equipamento recursos</code> — CPU, Memória, Uptime e Saúde\n"
            "7️⃣ <code>/equipamento logs</code> — Últimas linhas do log do MikroTik\n"
            "• <code>/equipamento</code> (sem argumentos) — Lista os equipamentos e botões\n"
            f"{olt_section}\n"
            "<b>📡 Equipamentos Disponíveis neste Bot:</b>\n"
            + ("\n".join(dev_lines) if dev_lines else "Nenhum equipamento ativo.")
        )

    return (
        f"🤖 <b>Bot BKPProvider — Comandos Remotos MikroTik</b>\n\n"
        "Use <code>/equipamento comando</code> para consultar em tempo real via SSH:\n\n"
        "<b>📌 Comandos por Equipamento:</b>\n"
        "1️⃣ <code>/equipamento ips</code> — Endereços IP das interfaces\n"
        "2️⃣ <code>/equipamento rotas</code> — Tabela de rotas ativas\n"
        "3️⃣ <code>/equipamento consumo</code> — Consumo em tempo real (RX/TX Mbps)\n"
        "4️⃣ <code>/equipamento portas</code> — Estado das portas Ethernet e serviços\n"
        "5️⃣ <code>/equipamento recursos</code> — CPU, Memória, Uptime e Saúde\n"
        "6️⃣ <code>/equipamento pingnet</code> — Teste de latência para a internet (8.8.8.8)\n"
        "7️⃣ <code>/equipamento logs</code> — Últimas linhas do log do MikroTik\n"
        "• <code>/equipamento</code> (sem argumentos) — Abre os botões interativos\n\n"
        "<b>📡 Equipamentos Disponíveis neste Bot:</b>\n"
        + ("\n".join(dev_lines) if dev_lines else "Nenhum equipamento ativo.")
    )


def _build_devices_overview(devices: list[dict]) -> tuple[str, dict]:
    lines = ["📡 <b>Resumo dos Equipamentos — BKPProvider</b>\n"]
    buttons = []
    row = []
    for d in devices:
        slug = _device_command_slug(d["name"])
        st = d.get("status") or "UP"
        icon = "🟢" if st == "UP" else "🔴"
        lat = f"{d['latency_ms']:.1f}ms" if d.get("latency_ms") is not None else "-"
        ver = d.get("ros_version_detail") or (d.get("ros_version") or "-").upper()
        lines.append(
            f"{icon} <b>{html.escape(d['name'])}</b> (<code>{html.escape(d['ip'])}</code>) • v{html.escape(ver)} • {lat} ➔ <code>/{slug}</code>"
        )
        if d.get("ssh_enabled"):
            row.append({"text": f"{icon} {d['name']}", "callback_data": f"devmenu:{d['id']}"})
            if len(row) == 2:
                buttons.append(row)
                row = []
    if row:
        buttons.append(row)

    lines.append("\n💡 <i>Toque em um equipamento abaixo para abrir seu menu interativo ou envie <code>/equipamento</code>.</i>")
    return "\n".join(lines), {"inline_keyboard": buttons}


async def _handle_incoming_message(session: aiohttp.ClientSession, bot_cfg: dict, msg: dict):
    token = bot_cfg["token"]
    chat = msg.get("chat") or {}
    chat_id = str(chat.get("id") or "")
    if not chat_id or chat_id not in bot_cfg["chats"]:
        return

    text = (msg.get("text") or "").strip()
    if not text.startswith("/"):
        return

    msg_id = msg.get("message_id")
    dest_scope_id = bot_cfg["chats"][chat_id]
    devices = _devices_for_chat(bot_cfg["all_devices"], dest_scope_id)

    parts = text.split(maxsplit=1)
    first_token = parts[0][1:]  # strip leading '/'
    if "@" in first_token:
        first_token = first_token.split("@", 1)[0]
    rest_text = parts[1] if len(parts) > 1 else ""

    cmd_lower = first_token.lower().strip()

    if cmd_lower in ("start", "ajuda", "help", "comandos", "menu"):
        await _send_bot_reply(session, token, chat_id, _build_help_message(devices, dest_scope_id=dest_scope_id), reply_to_message_id=msg_id)
        return

    if cmd_lower in ("equipamentos", "equipamento", "dispositivos", "dispositivo", "status", "rbs", "lista"):
        overview_text, kb = _build_devices_overview(devices)
        await _send_bot_reply(session, token, chat_id, overview_text, reply_to_message_id=msg_id, reply_markup=kb)
        return

    chat_has_olt = (dest_scope_id == 3) or any(_device_has_olt(d) for d in devices)

    # OLT Cianet Commands (exclusive to Marcos / OLT)
    if cmd_lower in ("onu", "olt", "sinal", "potencia", "onus_novas", "autofind", "autorizar", "auth", "desautorizar", "deauth", "delete_onu"):
        if not chat_has_olt:
            await _send_bot_reply(
                session, token, chat_id,
                "❌ Comando exclusivo para equipamentos com OLT configurada.",
                reply_to_message_id=msg_id,
            )
            return

    if cmd_lower in ("onu", "olt", "sinal", "potencia"):
        if not rest_text.strip():
            await _send_bot_reply(
                session, token, chat_id,
                "🔍 <b>Uso:</b> <code>/onu &lt;MAC ou Serial&gt;</code>\nExemplo: <code>/onu FHTTFE282DC4</code> ou <code>/onu ITBS0ACD111A</code>",
                reply_to_message_id=msg_id,
            )
            return
        await _tg_api_post(session, token, "sendChatAction", {"chat_id": chat_id, "action": "typing"})
        from app.olt_cianet import search_ont_async
        results = await search_ont_async(rest_text.strip())
        if not results:
            await _send_bot_reply(
                session, token, chat_id,
                f"❌ Nenhuma ONU encontrada na OLT com o termo <code>{html.escape(rest_text.strip())}</code>.",
                reply_to_message_id=msg_id,
            )
            return
        for r in results[:4]:
            rx = r.get("rx_dbm")
            rx_badge = ""
            if rx:
                try:
                    val = float(rx)
                    if -25.0 <= val <= -14.0:
                        rx_badge = " 🟢 (Ótimo)"
                    elif -28.0 <= val < -25.0:
                        rx_badge = " 🟡 (Atenção)"
                    else:
                        rx_badge = " 🔴 (Crítico/Abaixo)"
                except Exception:
                    pass

            status_icon = "🟢" if r.get("status") == "Online" else "🔴"
            text_resp = (
                f"📟 <b>ONU — OLT Cianet FD1608S</b>\n\n"
                f"• <b>Serial / MAC:</b> <code>{html.escape(r['sn'])}</code>\n"
                f"• <b>Porta PON:</b> <code>{r['port']}</code> | <b>ONT-ID:</b> <code>{r['ont_id']}</code>\n"
                f"• <b>Status:</b> {status_icon} <b>{html.escape(r['status'])}</b> ({html.escape(r.get('control', ''))})\n"
                f"• <b>Última Queda:</b> <code>{html.escape(r.get('down_cause') or '--')}</code>\n\n"
                f"📊 <b>Níveis de Potência Óptica:</b>\n"
                f"• <b>Rx ONU:</b> <code>{rx or '--'} dBm</code>{rx_badge}\n"
                f"• <b>Tx ONU:</b> <code>{r.get('tx_dbm') or '--'} dBm</code>\n"
                f"• <b>Rx na OLT:</b> <code>{r.get('olt_rx_dbm') or '--'} dBm</code>\n"
                f"• <b>Temperatura:</b> <code>{r.get('temp_c') or '--'} °C</code> | <b>Tensão:</b> <code>{r.get('voltage_v') or '--'} V</code>"
            )
            await _send_bot_reply(session, token, chat_id, text_resp, reply_to_message_id=msg_id)
        return

    if cmd_lower in ("onus_novas", "autofind"):
        await _tg_api_post(session, token, "sendChatAction", {"chat_id": chat_id, "action": "typing"})
        from app.olt_cianet import get_unauthorized_onts_async
        unauth = await get_unauthorized_onts_async()
        if not unauth:
            await _send_bot_reply(session, token, chat_id, "✅ <b>OLT Cianet:</b> Nenhuma ONU aguardando autorização no momento (autofind limpo).", reply_to_message_id=msg_id)
            return
        lines = ["🆕 <b>ONUs Aguardando Autorização (Autofind):</b>\n"]
        kb_rows = []
        for u in unauth:
            p_num = u.get("port", 1)
            sn_val = u.get("sn", "")
            lines.append(f"• <b>Porta PON {p_num}:</b> <code>{html.escape(sn_val)}</code>")
            kb_rows.append([{"text": f"✅ Autorizar {sn_val} (PON {p_num})", "callback_data": f"olt_auth:{p_num}:{sn_val}"}])
        await _send_bot_reply(session, token, chat_id, "\n".join(lines), reply_to_message_id=msg_id, reply_markup={"inline_keyboard": kb_rows} if kb_rows else None)
        return

    if cmd_lower in ("autorizar", "auth"):
        args = rest_text.strip().split()
        if len(args) < 2:
            await _send_bot_reply(
                session, token, chat_id,
                "Uso: <code>/autorizar &lt;porta_pon&gt; &lt;serial&gt;</code>\nExemplo: <code>/autorizar 1 TPLGE7530D38</code>",
                reply_to_message_id=msg_id
            )
            return
        await _tg_api_post(session, token, "sendChatAction", {"chat_id": chat_id, "action": "typing"})
        from app.olt_cianet import authorize_ont_async
        ok, res_msg = await authorize_ont_async(int(args[0]), args[1])
        icon = "✅" if ok else "❌"
        await _send_bot_reply(session, token, chat_id, f"{icon} {html.escape(res_msg)}", reply_to_message_id=msg_id)
        return

    if cmd_lower in ("desautorizar", "deauth", "delete_onu"):
        args = rest_text.strip().split()
        if len(args) < 2:
            await _send_bot_reply(
                session, token, chat_id,
                "Uso: <code>/desautorizar &lt;porta_pon&gt; &lt;ont_id&gt;</code>\nExemplo: <code>/desautorizar 1 48</code>",
                reply_to_message_id=msg_id
            )
            return
        await _tg_api_post(session, token, "sendChatAction", {"chat_id": chat_id, "action": "typing"})
        from app.olt_cianet import deauthorize_ont_async
        ok, res_msg = await deauthorize_ont_async(int(args[0]), int(args[1]))
        icon = "✅" if ok else "❌"
        await _send_bot_reply(session, token, chat_id, f"{icon} {html.escape(res_msg)}", reply_to_message_id=msg_id)
        return

    # Direct shortcuts for provider commands (/login, /gbic, /consumo, /clientes)
    provider_devs = [d for d in devices if d.get("device_type") == "provedor"]
    if not provider_devs:
        provider_devs = devices

    if cmd_lower in ("login", "user", "usuario"):
        login_target = rest_text.strip()
        if not login_target:
            await _send_bot_reply(
                session, token, chat_id,
                "🔍 <b>Uso:</b> <code>/login &lt;nome_do_pppoe&gt;</code>\n"
                "Exemplo: <code>/login joao</code>",
                reply_to_message_id=msg_id,
            )
            return

        if len(provider_devs) == 1:
            await _tg_api_post(session, token, "sendChatAction", {"chat_id": chat_id, "action": "typing"})
            reply_html = await _inspect_pppoe_login(provider_devs[0], login_target)
            await _send_bot_reply(
                session, token, chat_id, reply_html,
                reply_to_message_id=msg_id,
                reply_markup=_device_keyboard(provider_devs[0]["id"], provider_devs[0].get("device_type", "mikrotik"), has_olt=_device_has_olt(provider_devs[0])),
            )
            return

        # Multiple devices: prompt user with triage inline buttons
        kb_rows = []
        row = []
        for d in provider_devs:
            st = d.get("status") or "UP"
            icon = "🟢" if st == "UP" else "🔴"
            row.append({"text": f"{icon} {d['name']}", "callback_data": f"devlogin:{d['id']}:{login_target}"})
            if len(row) == 2:
                kb_rows.append(row)
                row = []
        if row:
            kb_rows.append(row)

        await _send_bot_reply(
            session, token, chat_id,
            f"🔍 <b>Em qual equipamento deseja consultar o login <code>{html.escape(login_target)}</code>?</b>",
            reply_to_message_id=msg_id,
            reply_markup={"inline_keyboard": kb_rows},
        )
        return

    if cmd_lower in ("gbic", "sfp", "otico", "fibra", "consumo", "trafego", "banda", "clientes", "pppoe"):
        sub_mapped = "clientes" if cmd_lower in ("clientes", "pppoe") else ("gbic" if cmd_lower in ("gbic", "sfp", "otico", "fibra") else "consumo")
        label_mapped = "Clientes Conectados" if sub_mapped == "clientes" else ("Sinal GBIC" if sub_mapped == "gbic" else "Consumo Geral")

        if len(provider_devs) == 1:
            target_dev = provider_devs[0]
            await _tg_api_post(session, token, "sendChatAction", {"chat_id": chat_id, "action": "typing"})
            reply_html = await _execute_bot_subcommand(target_dev, sub_mapped, rest_text)
            await _send_bot_reply(
                session, token, chat_id, reply_html,
                reply_to_message_id=msg_id,
                reply_markup=_device_keyboard(target_dev["id"], target_dev.get("device_type", "mikrotik"), has_olt=_device_has_olt(target_dev)),
            )
            return

        # Multiple devices: prompt user with triage inline buttons
        kb_rows = []
        row = []
        for d in provider_devs:
            st = d.get("status") or "UP"
            icon = "🟢" if st == "UP" else "🔴"
            row.append({"text": f"{icon} {d['name']}", "callback_data": f"devcmd:{d['id']}:{sub_mapped}"})
            if len(row) == 2:
                kb_rows.append(row)
                row = []
        if row:
            kb_rows.append(row)

        await _send_bot_reply(
            session, token, chat_id,
            f"⚙️ <b>Selecione o equipamento para consultar {label_mapped}:</b>",
            reply_to_message_id=msg_id,
            reply_markup={"inline_keyboard": kb_rows},
        )
        return

    # Support `/cmd <equipamento> <acao>` or `/<equipamento> <acao>`
    if cmd_lower in ("cmd", "rb", "equipamento", "dev") and rest_text:
        sub_parts = rest_text.split(maxsplit=1)
        first_token = sub_parts[0]
        rest_text = sub_parts[1] if len(sub_parts) > 1 else ""

    dev, subcmd, arg = _match_device_and_subcommand(first_token, rest_text, devices)
    if not dev:
        await _send_bot_reply(
            session,
            token,
            chat_id,
            f"❓ Equipamento ou comando <code>/{html.escape(first_token)}</code> não encontrado.\n"
            f"Digite /ajuda ou /equipamentos para ver a lista completa.",
            reply_to_message_id=msg_id,
        )
        return

    # If no subcommand was given (e.g. just `/balaio`), show device card + interactive inline buttons
    if not subcmd:
        card_text = _format_device_card(dev)
        await _send_bot_reply(
            session,
            token,
            chat_id,
            card_text,
            reply_to_message_id=msg_id,
            reply_markup=_device_keyboard(dev["id"], dev.get("device_type", "mikrotik"), has_olt=_device_has_olt(dev)),
        )
        return

    # Send typing/working indicator and execute subcommand
    await _tg_api_post(session, token, "sendChatAction", {"chat_id": chat_id, "action": "typing"})
    reply_html = await _execute_bot_subcommand(dev, subcmd, arg)
    await _send_bot_reply(
        session,
        token,
        chat_id,
        reply_html,
        reply_to_message_id=msg_id,
        reply_markup=_device_keyboard(dev["id"], dev.get("device_type", "mikrotik"), has_olt=_device_has_olt(dev)),
    )


async def _handle_callback_query(session: aiohttp.ClientSession, bot_cfg: dict, cb: dict):
    token = bot_cfg["token"]
    cb_id = cb.get("id")
    msg = cb.get("message") or {}
    chat = msg.get("chat") or {}
    chat_id = str(chat.get("id") or "")
    data = (cb.get("data") or "").strip()

    if not chat_id or chat_id not in bot_cfg["chats"]:
        if cb_id:
            await _tg_api_post(session, token, "answerCallbackQuery", {"callback_query_id": cb_id})
        return

    dest_scope_id = bot_cfg["chats"][chat_id]
    devices = _devices_for_chat(bot_cfg["all_devices"], dest_scope_id)

    if data.startswith("devmenu:"):
        dev_id_str = data.split(":", 1)[1]
        dev = next((d for d in devices if str(d["id"]) == dev_id_str), None)
        if cb_id:
            await _tg_api_post(session, token, "answerCallbackQuery", {"callback_query_id": cb_id})
        if dev:
            await _send_bot_reply(
                session,
                token,
                chat_id,
                _format_device_card(dev),
                reply_markup=_device_keyboard(dev["id"], dev.get("device_type", "mikrotik"), has_olt=_device_has_olt(dev)),
            )
        return

    if data.startswith("olt_del:"):
        chat_has_olt = (dest_scope_id == 3) or any(_device_has_olt(d) for d in devices)
        if not chat_has_olt:
            if cb_id:
                await _tg_api_post(session, token, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "Acesso não autorizado para esta OLT."})
            return
        parts = data.split(":", 3)
        if len(parts) >= 3:
            _, port_str, ont_id_str = parts[:3]
            sn_val = parts[3] if len(parts) > 3 else ""
            if cb_id:
                await _tg_api_post(session, token, "answerCallbackQuery", {"callback_query_id": cb_id, "text": f"Removendo ONU ID {ont_id_str} na PON {port_str}..."})
            from app.olt_cianet import deauthorize_ont_async
            ok, res_msg = await deauthorize_ont_async(int(port_str), int(ont_id_str))
            icon = "✅" if ok else "❌"
            await _send_bot_reply(session, token, chat_id, f"{icon} {html.escape(res_msg)}")
            return

    if data.startswith("olt_auth:"):
        chat_has_olt = (dest_scope_id == 3) or any(_device_has_olt(d) for d in devices)
        if not chat_has_olt:
            if cb_id:
                await _tg_api_post(session, token, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "Acesso não autorizado para esta OLT."})
            return
        parts = data.split(":", 2)
        if len(parts) == 3:
            _, port_str, sn_val = parts
            if cb_id:
                await _tg_api_post(session, token, "answerCallbackQuery", {"callback_query_id": cb_id, "text": f"Autorizando {sn_val} na PON {port_str}..."})
            from app.olt_cianet import authorize_ont_async
            ok, res_msg = await authorize_ont_async(int(port_str), sn_val)
            icon = "✅" if ok else "❌"
            await _send_bot_reply(session, token, chat_id, f"{icon} {html.escape(res_msg)}")
            return

    if data.startswith("devlogin:"):
        parts = data.split(":", 2)
        if len(parts) == 3:
            _, dev_id_str, login_target = parts
            dev = next((d for d in devices if str(d["id"]) == dev_id_str), None)
            if not dev:
                if cb_id:
                    await _tg_api_post(session, token, "answerCallbackQuery", {"callback_query_id": cb_id, "text": "Dispositivo não encontrado."})
                return
            if cb_id:
                await _tg_api_post(session, token, "answerCallbackQuery", {"callback_query_id": cb_id, "text": f"Consultando {login_target} em {dev['name']}..."})
            await _tg_api_post(session, token, "sendChatAction", {"chat_id": chat_id, "action": "typing"})
            reply_html = await _inspect_pppoe_login(dev, login_target)
            await _send_bot_reply(
                session,
                token,
                chat_id,
                reply_html,
                reply_markup=_device_keyboard(dev["id"], dev.get("device_type", "mikrotik"), has_olt=_device_has_olt(dev)),
            )
            return

    if data.startswith("devcmd:"):
        parts = data.split(":", 2)
        if len(parts) == 3:
            _, dev_id_str, subcmd = parts
            dev = next((d for d in devices if str(d["id"]) == dev_id_str), None)
            if not dev:
                if cb_id:
                    await _tg_api_post(
                        session,
                        token,
                        "answerCallbackQuery",
                        {"callback_query_id": cb_id, "text": "Dispositivo não encontrado."},
                    )
                return

            if cb_id:
                await _tg_api_post(
                    session,
                    token,
                    "answerCallbackQuery",
                    {"callback_query_id": cb_id, "text": f"Executando {subcmd} em {dev['name']}..."},
                )
            await _tg_api_post(session, token, "sendChatAction", {"chat_id": chat_id, "action": "typing"})
            reply_html = await _execute_bot_subcommand(dev, subcmd, "")
            await _send_bot_reply(
                session,
                token,
                chat_id,
                reply_html,
                reply_markup=_device_keyboard(dev["id"], dev.get("device_type", "mikrotik"), has_olt=_device_has_olt(dev)),
            )


async def _sync_bot_commands_menu(session: aiohttp.ClientSession, bot_cfg: dict):
    """
    Registers chat-scoped slash commands in Telegram's autocomplete menu via setMyCommands.
    Each group/chat receives strictly its own authorized devices, preventing leakage of other clients' equipment.
    """
    token = bot_cfg["token"]

    # 1. Reset global/default commands to a neutral base so unassigned groups don't see any devices
    default_commands = [
        {"command": "equipamentos", "description": "Resumo dos equipamentos autorizados"},
        {"command": "ajuda", "description": "Lista de comandos disponíveis"},
    ]
    await _tg_api_post(session, token, "setMyCommands", {"commands": default_commands, "scope": {"type": "default"}})

    # 2. Set specific commands tailored to each destination group/chat
    for chat_id, dest_scope_id in bot_cfg["chats"].items():
        if not chat_id:
            continue
        devices = _devices_for_chat(bot_cfg["all_devices"], dest_scope_id)
        commands = [
            {"command": "equipamentos", "description": "Resumo dos equipamentos autorizados"},
            {"command": "ajuda", "description": "Lista de comandos disponíveis"},
        ]
        seen_slugs = {"equipamentos", "ajuda"}

        has_provider = any(d.get("device_type") == "provedor" for d in devices)
        has_olt = (dest_scope_id == 3) or any(_device_has_olt(d) for d in devices)

        if has_provider:
            commands.append({"command": "login", "description": "Consultar conexão de login PPPoE (/login <nome>)"})
            commands.append({"command": "clientes", "description": "Total de clientes e bloqueados (/clientes)"})
            commands.append({"command": "gbic", "description": "Sinal óptico das portas GBIC/SFP (/gbic)"})
            commands.append({"command": "consumo", "description": "Consumo de banda em tempo real (/consumo)"})
            seen_slugs.update({"login", "clientes", "gbic", "consumo"})

        if has_olt:
            commands.append({"command": "onu", "description": "Consultar ONU e sinal óptico (/onu <MAC/SN>)"})
            commands.append({"command": "onus_novas", "description": "Ver ONUs aguardando autorização (autofind)"})
            seen_slugs.update({"onu", "onus_novas"})

        for d in devices:
            if not d.get("ssh_enabled"):
                continue
            slug = _device_command_slug(d["name"])
            if slug and slug not in seen_slugs and len(commands) < 95:
                seen_slugs.add(slug)
                desc = f"{d['name']} ({d['ip']})"
                if len(desc) > 90:
                    desc = desc[:90]
                commands.append({
                    "command": slug,
                    "description": desc,
                })

        try:
            cid_val = int(chat_id)
        except ValueError:
            cid_val = chat_id

        await _tg_api_post(
            session,
            token,
            "setMyCommands",
            {"commands": commands, "scope": {"type": "chat", "chat_id": cid_val}},
        )


async def telegram_bot_worker():
    """
    Background worker that polls Telegram updates across all configured bot tokens
    and executes remote MikroTik commands directly from Telegram chats.
    """
    offsets: dict[str, int] = {}
    last_menu_sync: dict[str, float] = {}
    initialized_tokens: set[str] = set()

    await asyncio.sleep(2)
    print("[TelegramBot] Interactive command worker started.")

    async with aiohttp.ClientSession() as session:
        while True:
            try:
                bot_configs = _get_authorized_bots_and_devices()
                if not bot_configs:
                    await asyncio.sleep(10)
                    continue

                now = time.monotonic()
                for bot_cfg in bot_configs:
                    tok = bot_cfg["token"]

                    # On first sight of token, flush old queued updates so we don't replay historical messages
                    if tok not in initialized_tokens:
                        res_init = await _tg_api_post(session, tok, "getUpdates", {"offset": -1, "timeout": 0})
                        if res_init.get("ok") and res_init.get("result"):
                            offsets[tok] = res_init["result"][-1]["update_id"] + 1
                        initialized_tokens.add(tok)

                    # Periodically sync `/` command autocomplete menu (every 5 minutes)
                    if now - last_menu_sync.get(tok, 0) > 300:
                        await _sync_bot_commands_menu(session, bot_cfg)
                        last_menu_sync[tok] = now

                    req_payload = {
                        "timeout": 2,
                        "allowed_updates": ["message", "callback_query"],
                    }
                    if tok in offsets:
                        req_payload["offset"] = offsets[tok]

                    res = await _tg_api_post(session, tok, "getUpdates", req_payload)
                    if not res.get("ok"):
                        continue

                    for upd in res.get("result") or []:
                        upd_id = upd.get("update_id", 0)
                        offsets[tok] = upd_id + 1

                        if "message" in upd:
                            asyncio.create_task(_handle_incoming_message(session, bot_cfg, upd["message"]))
                        elif "callback_query" in upd:
                            asyncio.create_task(_handle_callback_query(session, bot_cfg, upd["callback_query"]))

                await asyncio.sleep(1.0)
            except Exception as e:
                print(f"[TelegramBot Loop Error] {e}")
                await asyncio.sleep(5)
