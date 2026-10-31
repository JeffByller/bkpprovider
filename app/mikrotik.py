import asyncio
import base64
import datetime
import glob
import hashlib
import os
import re
import time

import paramiko

from app.config import BACKUPS_DIR
from app.crypto import decrypt_secret, generate_device_webhook_token, verify_device_webhook_token
from app.db import get_db, get_settings_typed, prune_command_logs
from app.telegram import send_telegram

# Concurrency limiter to protect the 1-vCPU VPS from too many simultaneous SSH threads
SSH_SEMAPHORE = asyncio.Semaphore(5)

_SAFE_TARGET_RE = re.compile(r"^[a-zA-Z0-9._:-]{1,64}$")
_FORBIDDEN_CMD_RE = re.compile(
    r"(reset-configuration|shutdown|reboot|format-drive|repartition|/file\s+remove|/user\s+remove|/system\s+package\s+uninstall)",
    re.IGNORECASE,
)

# Catalog of Quick Actions supporting RouterOS v6 and v7 differences
QUICK_ACTIONS = {
    "system_info": {
        "label": "Recursos e Hardware",
        "description": "Versão do RouterOS, Uptime, CPU, Memória, RouterBOARD e Saúde",
        "v6": "/system resource print without-paging; /system routerboard print without-paging; /system health print without-paging",
        "v7": "/system resource print without-paging; /system routerboard print without-paging; /system health print without-paging",
    },
    "interfaces": {
        "label": "Interfaces e Tráfego",
        "description": "Lista de interfaces, estado do link e contadores de pacotes/bytes",
        "v6": "/interface print stats without-paging",
        "v7": "/interface print stats without-paging",
    },
    "traffic_live": {
        "label": "Consumo Agora (Tempo Real)",
        "description": "Consumo instantâneo (RX/TX bps) em todas as interfaces ativas",
        "v6": ':foreach i in=[/interface find running=yes] do={ :local n [/interface get $i name]; :local m [/interface monitor-traffic $i once as-value]; :put ($n . "  |  RX: " . ($m->"rx-bits-per-second") . " bps  |  TX: " . ($m->"tx-bits-per-second") . " bps") }',
        "v7": ':foreach i in=[/interface find running=yes] do={ :local n [/interface get $i name]; :local m [/interface monitor-traffic $i once as-value]; :put ($n . "  |  RX: " . ($m->"rx-bits-per-second") . " bps  |  TX: " . ($m->"tx-bits-per-second") . " bps") }',
    },
    "ip_addresses": {
        "label": "Endereços IP",
        "description": "Endereços IPv4 configurados nas interfaces",
        "v6": "/ip address print without-paging",
        "v7": "/ip address print without-paging",
    },
    "routes": {
        "label": "Rotas Ativas",
        "description": "Tabela de roteamento principal (rotas ativas)",
        "v6": "/ip route print without-paging where active=yes",
        "v7": "/ip route print without-paging where active",
    },
    "failover_status": {
        "label": "Failover & Netwatch",
        "description": "Rotas Principal/Backup, rotas de monitoramento e estado do Netwatch",
        "v6": "/ip route print detail without-paging; /tool netwatch print detail without-paging",
        "v7": "/ip route print detail without-paging; /tool netwatch print detail without-paging",
    },
    "bgp_status": {
        "label": "Status BGP (v6/v7)",
        "description": "Estado dos peers/sessões BGP compatível com v6 e v7",
        "v6": "/routing bgp peer print status without-paging",
        "v7": "/routing bgp session print without-paging",
    },
    "pppoe_active": {
        "label": "PPPoE Ativos",
        "description": "Total de sessões PPPoE ativas e listagem de clientes conectados",
        "v6": "/ppp active print count-only; /ppp active print without-paging",
        "v7": "/ppp active print count-only; /ppp active print without-paging",
    },
    "dhcp_leases": {
        "label": "Leases DHCP",
        "description": "Concessões ativas dos servidores DHCP",
        "v6": "/ip dhcp-server lease print without-paging where status=bound",
        "v7": "/ip dhcp-server lease print without-paging where status=bound",
    },
    "arp_table": {
        "label": "Tabela ARP",
        "description": "Vizinhos IP/MAC aprendidos na tabela ARP",
        "v6": "/ip arp print without-paging",
        "v7": "/ip arp print without-paging",
    },
    "firewall_filter": {
        "label": "Firewall Filter",
        "description": "Regras de filtro de firewall e estatísticas de pacotes",
        "v6": "/ip firewall filter print stats without-paging",
        "v7": "/ip firewall filter print stats without-paging",
    },
    "firewall_nat": {
        "label": "Firewall NAT",
        "description": "Regras de NAT (srcnat / dstnat / masquerade)",
        "v6": "/ip firewall nat print without-paging",
        "v7": "/ip firewall nat print without-paging",
    },
    "snmp_config": {
        "label": "Configuração SNMP",
        "description": "Estado atual do serviço SNMP e communities cadastradas",
        "v6": "/snmp print without-paging; /snmp community print detail without-paging",
        "v7": "/snmp print without-paging; /snmp community print detail without-paging",
    },
    "ip_services": {
        "label": "Portas e Serviços",
        "description": "Serviços de gerência habilitados (SSH, Winbox, WWW, API, SNMP)",
        "v6": "/ip service print without-paging; /user print without-paging",
        "v7": "/ip service print without-paging; /user print without-paging",
    },
    "recent_logs": {
        "label": "Últimos Logs",
        "description": "Eventos recentes do log do sistema",
        "v6": "/log print without-paging",
        "v7": "/log print without-paging",
    },
    "tool_ping": {
        "label": "Ping (a partir da RB)",
        "description": "Executa 4 pacotes ICMP a partir do próprio roteador para um destino",
        "requires_param": True,
        "param_label": "IP ou Host de Destino (ex: 8.8.8.8)",
        "v6": "/tool ping {target} count=4",
        "v7": "/tool ping {target} count=4",
    },
    "tool_traceroute": {
        "label": "Traceroute (a partir da RB)",
        "description": "Rastreia a rota a partir do roteador até um destino (máx 15 saltos)",
        "requires_param": True,
        "param_label": "IP ou Host de Destino (ex: 1.1.1.1)",
        "v6": "/tool traceroute {target} count=1 max-hops=15",
        "v7": "/tool traceroute {target} count=1 max-hops=15",
    },
}


def clean_device_name(name: str) -> str:
    return "".join(x for x in name if x.isalnum() or x in ("_", "-"))


def cleanup_old_backups(clean_name: str, ip: str, keep: int = 7):
    try:
        pattern = os.path.join(BACKUPS_DIR, f"{clean_name}_{ip}_*.txt")
        files = sorted(glob.glob(pattern))
        if len(files) > keep:
            for f in files[:-keep]:
                try:
                    if os.path.exists(f):
                        os.remove(f)
                except Exception as e:
                    print(f"[Backup Cleanup Error] {f}: {e}")
    except Exception as e:
        print(f"[Cleanup Error] {e}")


def _exec_ssh_cmd(ssh: paramiko.SSHClient, cmd: str, timeout: int = 20) -> tuple[int, str, str]:
    """Executes an SSH command and waits for completion with timeout."""
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    stdin.close()
    out_bytes = stdout.read()
    err_bytes = stderr.read()
    exit_code = stdout.channel.recv_exit_status()
    out_text = out_bytes.decode("utf-8", errors="replace").replace("\r\n", "\n")
    err_text = err_bytes.decode("utf-8", errors="replace").replace("\r\n", "\n")
    return exit_code, out_text, err_text


def _get_host_key_fingerprint(ssh: paramiko.SSHClient) -> str:
    try:
        transport = ssh.get_transport()
        if not transport:
            return ""
        key = transport.get_remote_server_key()
        digest = hashlib.sha256(key.asbytes()).digest()
        b64 = base64.b64encode(digest).decode("ascii").rstrip("=")
        return f"{key.get_name()}:SHA256:{b64}"
    except Exception:
        return ""


def _parse_resource_output(text: str) -> dict:
    """Parses RouterOS `/system resource print` output."""
    info = {
        "ros_version": "auto",
        "ros_version_detail": "",
        "board_name": "",
        "architecture": "",
        "uptime_str": "",
        "cpu_load": None,
        "memory_total_mb": None,
        "memory_used_mb": None,
        "memory_used_pct": None,
    }
    free_mem = None
    total_mem = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if k == "version":
            ver_token = v.split()[0].strip()
            info["ros_version_detail"] = ver_token
            if ver_token.startswith("7."):
                info["ros_version"] = "v7"
            elif ver_token.startswith("6."):
                info["ros_version"] = "v6"
        elif k == "board-name":
            info["board_name"] = v
        elif k == "architecture-name":
            info["architecture"] = v
        elif k == "uptime":
            info["uptime_str"] = v
        elif k == "cpu-load":
            m = re.search(r"(\d+)", v)
            if m:
                info["cpu_load"] = int(m.group(1))
        elif k == "free-memory":
            free_mem = _parse_ros_size_mb(v)
        elif k == "total-memory":
            total_mem = _parse_ros_size_mb(v)

    if total_mem and total_mem > 0 and free_mem is not None:
        used = max(0.0, total_mem - free_mem)
        info["memory_total_mb"] = round(total_mem, 1)
        info["memory_used_mb"] = round(used, 1)
        info["memory_used_pct"] = round((used / total_mem) * 100.0, 1)
    return info


def _parse_ros_size_mb(val_str: str) -> float | None:
    """Converts RouterOS memory strings like '128.0MiB', '1048576', '45.2KiB', '1.0GiB' into MB."""
    s = val_str.strip()
    m = re.match(r"^([\d.]+)\s*([a-zA-Z]*)$", s)
    if not m:
        return None
    num = float(m.group(1))
    unit = m.group(2).lower()
    if unit in ("gib", "gb", "g"):
        return num * 1024.0
    if unit in ("mib", "mb", "m"):
        return num
    if unit in ("kib", "kb", "k"):
        return num / 1024.0
    # Raw bytes
    return num / (1024.0 * 1024.0)


def _connect_ssh(ip: str, port: int, username: str, password_plain: str, timeout: int = 10) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        ip,
        port=int(port or 22),
        username=username,
        password=password_plain,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return ssh


def _probe_ssh_sync(ip: str, port: int, username: str, password_plain: str) -> tuple[bool, dict, str]:
    ssh = None
    try:
        ssh = _connect_ssh(ip, port, username, password_plain, timeout=10)
        fingerprint = _get_host_key_fingerprint(ssh)
        _, out, _ = _exec_ssh_cmd(ssh, "/system resource print without-paging", timeout=10)
        info = _parse_resource_output(out)
        info["ssh_host_key"] = fingerprint
        return True, info, "Conexão SSH estabelecida e RouterOS identificado com sucesso!"
    except Exception as e:
        return False, {}, str(e)
    finally:
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass


async def probe_device_ssh(dev: dict) -> tuple[bool, dict, str]:
    """Tests SSH connectivity, discovers RouterOS v6/v7, hardware info, and updates DB."""
    password_plain = decrypt_secret(dev["ssh_password"])
    if not dev.get("ssh_username") or not password_plain:
        return False, {}, "Credenciais SSH (usuário/senha) não configuradas neste dispositivo."

    async with SSH_SEMAPHORE:
        loop = asyncio.get_running_loop()
        ok, info, msg = await loop.run_in_executor(
            None,
            _probe_ssh_sync,
            dev["ip"],
            dev["ssh_port"],
            dev["ssh_username"],
            password_plain,
        )

    if ok and info:
        conn = get_db()
        try:
            c = conn.cursor()
            c.execute(
                """
                UPDATE devices
                SET ros_version = COALESCE(NULLIF(?, 'auto'), ros_version),
                    ros_version_detail = COALESCE(NULLIF(?, ''), ros_version_detail),
                    board_name = COALESCE(NULLIF(?, ''), board_name),
                    architecture = COALESCE(NULLIF(?, ''), architecture),
                    uptime_str = COALESCE(NULLIF(?, ''), uptime_str),
                    cpu_load = COALESCE(?, cpu_load),
                    memory_total_mb = COALESCE(?, memory_total_mb),
                    memory_used_mb = COALESCE(?, memory_used_mb),
                    memory_used_pct = COALESCE(?, memory_used_pct),
                    ssh_host_key = COALESCE(NULLIF(?, ''), ssh_host_key)
                WHERE id = ?
                """,
                (
                    info.get("ros_version"),
                    info.get("ros_version_detail"),
                    info.get("board_name"),
                    info.get("architecture"),
                    info.get("uptime_str"),
                    info.get("cpu_load"),
                    info.get("memory_total_mb"),
                    info.get("memory_used_mb"),
                    info.get("memory_used_pct"),
                    info.get("ssh_host_key"),
                    dev["id"],
                ),
            )
            conn.commit()
        finally:
            conn.close()

    return ok, info, msg


def _backup_mikrotik_sync(
    clean_name: str,
    ip: str,
    port: int,
    username: str,
    password_plain: str,
    known_ros_version: str,
    filename: str,
    retention: int = 7,
) -> tuple[bool, str, int, dict]:
    os.makedirs(BACKUPS_DIR, exist_ok=True)
    cleanup_old_backups(clean_name, ip, keep=max(retention - 1, 1))

    ssh = None
    sftp = None
    try:
        ssh = _connect_ssh(ip, port, username, password_plain, timeout=12)
        fingerprint = _get_host_key_fingerprint(ssh)

        # 1. Detect RouterOS version & system resource in the same session
        _, res_out, _ = _exec_ssh_cmd(ssh, "/system resource print without-paging", timeout=10)
        info = _parse_resource_output(res_out)
        info["ssh_host_key"] = fingerprint
        ros_ver = info["ros_version"] if info["ros_version"] in ("v6", "v7") else (known_ros_version or "v6")

        local_path = os.path.join(BACKUPS_DIR, f"{filename}.txt")
        backup_content = ""

        # Strategy 1: Direct SSH stream export (works with read-only/no-ftp user groups and avoids flash disk wear)
        export_stream_cmds = (
            ["/export show-sensitive compact", "/export compact", "/export"]
            if ros_ver == "v7"
            else ["/export compact", "/export"]
        )
        for e_cmd in export_stream_cmds:
            try:
                code, out_text, err_text = _exec_ssh_cmd(ssh, e_cmd, timeout=45)
                if len(out_text.strip()) > 100 and ("RouterOS" in out_text or "/interface" in out_text or "/ip" in out_text):
                    backup_content = out_text
                    break
            except Exception:
                pass

        if backup_content:
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(backup_content)
        else:
            # Strategy 2: Fallback to remote file generation and SFTP transfer
            remote_file_name = f"bkp_{filename}"
            if ros_ver == "v7":
                _, exp_out, exp_err = _exec_ssh_cmd(
                    ssh, f"/export show-sensitive file={remote_file_name}", timeout=35
                )
                if "expected end of command" in exp_out.lower() or "not enough permissions" in exp_out.lower() or exp_err:
                    _exec_ssh_cmd(ssh, f"/export file={remote_file_name}", timeout=35)
            else:
                _exec_ssh_cmd(ssh, f"/export file={remote_file_name}", timeout=35)

            sftp = ssh.open_sftp()
            remote_candidates = [f"{remote_file_name}.rsc", f"/{remote_file_name}.rsc", remote_file_name]
            remote_target = None
            for _ in range(6):
                for cand in remote_candidates:
                    try:
                        st = sftp.stat(cand)
                        if st.st_size and st.st_size > 0:
                            remote_target = cand
                            break
                    except Exception:
                        continue
                if remote_target:
                    break
                time.sleep(0.5)

            if not remote_target:
                remote_target = f"{remote_file_name}.rsc"

            try:
                sftp.get(remote_target, local_path)
            except Exception:
                sftp.get(remote_file_name, local_path)
                remote_target = remote_file_name

            try:
                clean_rem = remote_target.lstrip("/")
                _exec_ssh_cmd(ssh, f'/file remove "{clean_rem}"', timeout=8)
            except Exception:
                pass

        file_size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
        cleanup_old_backups(clean_name, ip, keep=retention)
        ver_label = info.get("ros_version_detail") or ros_ver
        return True, f"Backup concluído ({ver_label}, {file_size / 1024:.1f} KB)", file_size, info
    except Exception as e:
        return False, str(e), 0, {}
    finally:
        if sftp:
            try:
                sftp.close()
            except Exception:
                pass
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass


async def run_backup_for_device(dev, manual: bool = False) -> tuple[bool, str]:
    dev_id = dev["id"]
    name = dev["name"]
    ip = dev["ip"]
    port = dev["ssh_port"] or 22
    username = dev["ssh_username"] or ""
    password_plain = decrypt_secret(dev["ssh_password"])

    if not username or not password_plain:
        return False, "Credenciais SSH (usuário/senha) não configuradas para este dispositivo."

    settings = get_settings_typed()
    date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_name = clean_device_name(name)
    filename = f"{clean_name}_{ip}_{date_str}"

    t0 = time.monotonic()
    async with SSH_SEMAPHORE:
        loop = asyncio.get_running_loop()
        success, msg, file_size, info = await loop.run_in_executor(
            None,
            _backup_mikrotik_sync,
            clean_name,
            ip,
            port,
            username,
            password_plain,
            dev["ros_version"],
            filename,
            settings["backup_retention"],
        )
    duration_ms = int((time.monotonic() - t0) * 1000)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    trigger_type = "MANUAL" if manual else "AUTO"
    ros_detail = info.get("ros_version_detail") or dev["ros_version_detail"] or dev["ros_version"] or ""

    conn = get_db()
    try:
        c = conn.cursor()
        if success:
            c.execute(
                """
                UPDATE devices
                SET last_backup = ?,
                    last_backup_status = 'SUCCESS',
                    last_backup_message = ?,
                    ros_version = COALESCE(NULLIF(?, 'auto'), ros_version),
                    ros_version_detail = COALESCE(NULLIF(?, ''), ros_version_detail),
                    board_name = COALESCE(NULLIF(?, ''), board_name),
                    architecture = COALESCE(NULLIF(?, ''), architecture),
                    uptime_str = COALESCE(NULLIF(?, ''), uptime_str),
                    cpu_load = COALESCE(?, cpu_load),
                    memory_total_mb = COALESCE(?, memory_total_mb),
                    memory_used_mb = COALESCE(?, memory_used_mb),
                    memory_used_pct = COALESCE(?, memory_used_pct),
                    ssh_host_key = COALESCE(NULLIF(?, ''), ssh_host_key)
                WHERE id = ?
                """,
                (
                    now,
                    msg,
                    info.get("ros_version"),
                    info.get("ros_version_detail"),
                    info.get("board_name"),
                    info.get("architecture"),
                    info.get("uptime_str"),
                    info.get("cpu_load"),
                    info.get("memory_total_mb"),
                    info.get("memory_used_mb"),
                    info.get("memory_used_pct"),
                    info.get("ssh_host_key"),
                    dev_id,
                ),
            )
        else:
            c.execute(
                "UPDATE devices SET last_backup_status = ?, last_backup_message = ? WHERE id = ?",
                (f"FAILED: {msg}", msg, dev_id),
            )

        c.execute(
            """
            INSERT INTO backup_history (
                device_id, device_name, device_ip, ros_version,
                filename, size_bytes, status, trigger_type, duration_ms, message, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                dev_id,
                name,
                ip,
                ros_detail,
                f"{filename}.txt" if success else "",
                file_size,
                "SUCCESS" if success else "FAILED",
                trigger_type,
                duration_ms,
                msg,
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    tag = "Manual" if manual else "Automático"
    dest_id = dev["telegram_destination_id"] if "telegram_destination_id" in dev.keys() else None
    if success:
        await send_telegram(
            f"✅ <b>[Backup {tag}]</b>\nDispositivo: <b>{name}</b> (<code>{ip}</code>)\n{msg}",
            dest_id,
        )
    else:
        await send_telegram(
            f"❌ <b>[Falha no Backup {tag}]</b>\nDispositivo: <b>{name}</b> (<code>{ip}</code>)\nErro: <code>{msg}</code>",
            dest_id,
        )

    return success, msg


async def run_all_backups():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE active=1 AND backup_enabled=1")
        devices = [dict(r) for r in c.fetchall()]
        conn.close()

        if not devices:
            return

        # Execute concurrently bounded by SSH_SEMAPHORE (up to 5 in parallel)
        await asyncio.gather(
            *(run_backup_for_device(dev, manual=False) for dev in devices),
            return_exceptions=True,
        )
    except Exception as e:
        print(f"[Mikrotik Backup Error] {e}")


async def mikrotik_worker():
    last_executed_slot = None
    while True:
        try:
            settings = get_settings_typed()
            now = datetime.datetime.now()
            b_hour = settings.get("backup_hour", 12)
            b_minute = settings.get("backup_minute", 0)
            current_slot = f"{now.strftime('%Y-%m-%d')}_{b_hour:02d}_{b_minute:02d}"

            if now.hour == b_hour and now.minute == b_minute:
                if last_executed_slot != current_slot:
                    last_executed_slot = current_slot
                    print(f"[Mikrotik Worker] Executando backup automático agendado ({b_hour:02d}:{b_minute:02d})...")
                    await run_all_backups()
        except Exception as e:
            print(f"[Mikrotik Worker Error] {e}")

        await asyncio.sleep(15)


def _run_ssh_command_sync(
    ip: str,
    port: int,
    username: str,
    password_plain: str,
    known_ros_version: str,
    action_key: str,
    target_param: str = "",
    custom_cmd: str = "",
) -> tuple[bool, str, str, dict]:
    ssh = None
    try:
        ssh = _connect_ssh(ip, port, username, password_plain, timeout=10)
        fingerprint = _get_host_key_fingerprint(ssh)
        _, res_out, _ = _exec_ssh_cmd(ssh, "/system resource print without-paging", timeout=10)
        info = _parse_resource_output(res_out)
        info["ssh_host_key"] = fingerprint
        ros_ver = info["ros_version"] if info["ros_version"] in ("v6", "v7") else (known_ros_version if known_ros_version in ("v6", "v7") else "v6")

        if action_key == "custom":
            cmd_to_run = custom_cmd.strip()
        else:
            spec = QUICK_ACTIONS.get(action_key)
            if not spec:
                return False, "", f"Ação rápida '{action_key}' desconhecida.", info
            template = spec.get(ros_ver) or spec.get("v6")
            if spec.get("requires_param"):
                cmd_to_run = template.format(target=target_param)
            else:
                cmd_to_run = template

        if action_key == "system_info":
            # Reuse already fetched resource output and append routerboard + health
            _, extra_out, _ = _exec_ssh_cmd(
                ssh,
                "/system routerboard print without-paging; /system health print without-paging",
                timeout=12,
            )
            full_out = f"=== /system resource print ===\n{res_out.strip()}\n\n=== RouterBOARD & Health ===\n{extra_out.strip()}"
            return True, cmd_to_run, full_out, info

        _, out, err = _exec_ssh_cmd(ssh, cmd_to_run, timeout=20)
        combined = out
        if err and err.strip():
            combined = f"{out}\n[STDERR]\n{err}".strip()

        # Trim excessive log output to last 100 lines for readability
        if action_key == "recent_logs":
            lines = combined.splitlines()
            if len(lines) > 100:
                combined = "\n".join(lines[-100:])

        return True, cmd_to_run, combined or "(Comando executado sem saída de texto)", info
    except Exception as e:
        return False, custom_cmd or action_key, f"Erro SSH: {e}", {}
    finally:
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass


async def execute_device_command(
    dev: dict,
    action_key: str,
    target_param: str = "",
    custom_cmd: str = "",
    client_ip: str = "",
) -> dict:
    """Executes a quick action or authorized custom command via SSH and records audit log."""
    if not dev.get("ssh_enabled"):
        return {"ok": False, "error": "O acesso remoto SSH está desabilitado para este dispositivo."}

    password_plain = decrypt_secret(dev["ssh_password"])
    if not dev.get("ssh_username") or not password_plain:
        return {"ok": False, "error": "Credenciais SSH (usuário/senha) não cadastradas para este dispositivo."}

    if action_key == "custom":
        cmd_clean = (custom_cmd or "").strip()
        if not cmd_clean:
            return {"ok": False, "error": "Informe um comando RouterOS para executar."}
        if len(cmd_clean) > 300:
            return {"ok": False, "error": "Comando excede o tamanho máximo permitido (300 caracteres)."}
        if _FORBIDDEN_CMD_RE.search(cmd_clean):
            return {
                "ok": False,
                "error": "Comando bloqueado pela política de segurança (operações destrutivas/reboot não são permitidas via console rápido).",
            }
    else:
        spec = QUICK_ACTIONS.get(action_key)
        if not spec:
            return {"ok": False, "error": "Ação rápida inválida."}
        if spec.get("requires_param"):
            target_param = (target_param or "").strip()
            if not target_param or not _SAFE_TARGET_RE.match(target_param):
                return {"ok": False, "error": "Parâmetro de destino inválido. Informe um IP ou hostname válido."}

    t0 = time.monotonic()
    async with SSH_SEMAPHORE:
        loop = asyncio.get_running_loop()
        ok, cmd_executed, output, info = await loop.run_in_executor(
            None,
            _run_ssh_command_sync,
            dev["ip"],
            dev["ssh_port"],
            dev["ssh_username"],
            password_plain,
            dev["ros_version"],
            action_key,
            target_param,
            custom_cmd,
        )
    duration_ms = int((time.monotonic() - t0) * 1000)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    try:
        c = conn.cursor()
        if info:
            c.execute(
                """
                UPDATE devices
                SET ros_version = COALESCE(NULLIF(?, 'auto'), ros_version),
                    ros_version_detail = COALESCE(NULLIF(?, ''), ros_version_detail),
                    board_name = COALESCE(NULLIF(?, ''), board_name),
                    architecture = COALESCE(NULLIF(?, ''), architecture),
                    uptime_str = COALESCE(NULLIF(?, ''), uptime_str),
                    cpu_load = COALESCE(?, cpu_load),
                    memory_total_mb = COALESCE(?, memory_total_mb),
                    memory_used_mb = COALESCE(?, memory_used_mb),
                    memory_used_pct = COALESCE(?, memory_used_pct),
                    ssh_host_key = COALESCE(NULLIF(?, ''), ssh_host_key)
                WHERE id = ?
                """,
                (
                    info.get("ros_version"),
                    info.get("ros_version_detail"),
                    info.get("board_name"),
                    info.get("architecture"),
                    info.get("uptime_str"),
                    info.get("cpu_load"),
                    info.get("memory_total_mb"),
                    info.get("memory_used_mb"),
                    info.get("memory_used_pct"),
                    info.get("ssh_host_key"),
                    dev["id"],
                ),
            )
        preview = (output or "")[:2000]
        c.execute(
            """
            INSERT INTO command_logs (
                device_id, device_name, device_ip, action_key, command_executed,
                status, output_preview, duration_ms, client_ip, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                dev["id"],
                dev["name"],
                dev["ip"],
                action_key,
                cmd_executed,
                "SUCCESS" if ok else "ERROR",
                preview,
                duration_ms,
                client_ip,
                now,
            ),
        )
        prune_command_logs(c, 200)
        conn.commit()
    finally:
        conn.close()

    return {
        "ok": ok,
        "command": cmd_executed,
        "output": output,
        "duration_ms": duration_ms,
        "ros_version": info.get("ros_version_detail") or dev.get("ros_version_detail") or dev.get("ros_version"),
        "board_name": info.get("board_name") or dev.get("board_name"),
        "timestamp": now,
    }


# ---------- Failover & Netwatch (2-Step Analyze + Configure + Telegram Alert) ----------

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_SAFE_GW_RE = re.compile(r"^[a-zA-Z0-9._:/ -]{1,64}$")
_SAFE_INTERVAL_RE = re.compile(r"^\d+[smhd]$|^\d{2}:\d{2}:\d{2}$")

# Tracks recent failover provisioning timestamps & last link state per device to prevent duplicate/boot spam
_FAILOVER_SETUP_GRACE: dict[int, float] = {}
_FAILOVER_LAST_EVENT: dict[tuple[int, str], tuple[str, float]] = {}

FAILOVER_WEBHOOK_BASE_URL = "https://bkp.jeffgsan.com.br"
FAILOVER_SERVER_IP = "38.225.221.159"


def _parse_ros_detail_blocks(text: str) -> list[dict]:
    """
    Parses RouterOS `print detail without-paging` output into a list of dicts.
    Supports both v6 and v7 multi-line item blocks, flags (R, X, D, A, S, b...),
    `;;; comment` lines, and `key="value"` / `key=value` attributes.
    """
    items = []
    if not text:
        return items

    current_lines = []
    for raw_line in text.splitlines():
        if not raw_line.strip():
            if current_lines:
                items.append(_parse_single_ros_block(current_lines))
                current_lines = []
            continue
        if re.match(r"^\s*\d+\s+", raw_line):
            if current_lines:
                items.append(_parse_single_ros_block(current_lines))
            current_lines = [raw_line]
        elif current_lines:
            current_lines.append(raw_line)

    if current_lines:
        items.append(_parse_single_ros_block(current_lines))

    return [i for i in items if i]


def _parse_single_ros_block(lines: list[str]) -> dict:
    first = lines[0]
    m_head = re.match(r"^\s*(\d+)\s+([A-Za-z*]*)\s*(.*)$", first)
    if not m_head:
        return {}

    idx_str, raw_flags, rest_first = m_head.group(1), m_head.group(2), m_head.group(3)
    # Check if `rest_first` starts with key=value (meaning there were no flags, or flags were part of key)
    if "=" in raw_flags:
        rest_first = f"{raw_flags} {rest_first}"
        raw_flags = ""

    entry = {
        "_id": idx_str,
        "_flags": raw_flags,
        "comment": "",
    }

    body_parts = []
    if rest_first.strip().startswith(";;;"):
        entry["comment"] = rest_first.strip()[3:].strip()
    else:
        body_parts.append(rest_first)

    for line in lines[1:]:
        s = line.strip()
        if s.startswith(";;;"):
            if not entry["comment"]:
                entry["comment"] = s[3:].strip()
            else:
                entry["comment"] += " " + s[3:].strip()
        else:
            body_parts.append(s)

    full_body = " ".join(body_parts)
    # First extract quoted scripts (up-script, down-script, test-script) so inner key=value tokens don't collide
    for script_key in ("up-script", "down-script", "test-script"):
        m_sc = re.search(rf'{script_key}="((?:\\.|[^"\\])*)"', full_body)
        if m_sc:
            entry[script_key] = m_sc.group(1)
            full_body = full_body[: m_sc.start()] + " " + full_body[m_sc.end() :]

    # Match key=value where value may be quoted or unquoted (including spaces in v6 print detail) up to next key=
    key_matches = list(re.finditer(r'(?:^|\s)([a-zA-Z0-9._-]+)=', full_body))
    for idx, m in enumerate(key_matches):
        k = m.group(1)
        val_start = m.end()
        val_end = key_matches[idx + 1].start() if (idx + 1) < len(key_matches) else len(full_body)
        raw_val = full_body[val_start:val_end].strip()
        if len(raw_val) >= 2 and raw_val.startswith('"') and raw_val.endswith('"'):
            raw_val = raw_val[1:-1]
        if k == "comment" and entry.get("comment"):
            continue
        entry[k] = raw_val

    return entry


def _quote_ros_val(val: str) -> str:
    s = str(val).strip()
    if not s:
        return '""'
    if re.search(r'[\s;$"\\]', s):
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return s


def _analyze_failover_ssh_sync(
    ip: str,
    port: int,
    username: str,
    password_plain: str,
    known_ros_version: str,
) -> tuple[bool, dict, str]:
    ssh = None
    try:
        ssh = _connect_ssh(ip, port, username, password_plain, timeout=12)
        fingerprint = _get_host_key_fingerprint(ssh)

        combined_cmd = (
            ':put "===SECTION:RES==="; /system resource print without-paging; '
            ':put "===SECTION:ID==="; /system identity print without-paging; '
            ':put "===SECTION:PPPOE==="; /interface pppoe-client print detail without-paging; '
            ':put "===SECTION:DHCP==="; /ip dhcp-client print detail without-paging; '
            ':put "===SECTION:ROUTES==="; /ip route print detail without-paging; '
            ':put "===SECTION:NETWATCH==="; /tool netwatch print detail without-paging; '
            ':put "===SECTION:NAT==="; /ip firewall nat print detail without-paging where chain=srcnat; '
            ':put "===SECTION:ETHER==="; /interface ethernet print detail without-paging'
        )
        _, raw_out, _ = _exec_ssh_cmd(ssh, combined_cmd, timeout=20)

        sections = {}
        cur_sec = "NONE"
        for line in raw_out.splitlines():
            m_sec = re.match(r"^===SECTION:([A-Z]+)===$", line.strip())
            if m_sec:
                cur_sec = m_sec.group(1)
                sections[cur_sec] = []
            else:
                sections.setdefault(cur_sec, []).append(line)

        res_text = "\n".join(sections.get("RES", []))
        id_text = "\n".join(sections.get("ID", []))
        pppoe_text = "\n".join(sections.get("PPPOE", []))
        dhcp_text = "\n".join(sections.get("DHCP", []))
        routes_text = "\n".join(sections.get("ROUTES", []))
        netwatch_text = "\n".join(sections.get("NETWATCH", []))
        nat_text = "\n".join(sections.get("NAT", []))
        ether_text = "\n".join(sections.get("ETHER", []))

        info = _parse_resource_output(res_text)
        info["ssh_host_key"] = fingerprint
        ros_ver = (
            info["ros_version"]
            if info["ros_version"] in ("v6", "v7")
            else (known_ros_version if known_ros_version in ("v6", "v7") else "v6")
        )
        info["ros_version"] = ros_ver

        identity = ""
        for line in id_text.splitlines():
            if "name:" in line.lower():
                identity = line.split(":", 1)[1].strip()
                break

        pppoe_items = _parse_ros_detail_blocks(pppoe_text)
        dhcp_items = _parse_ros_detail_blocks(dhcp_text)
        route_items = _parse_ros_detail_blocks(routes_text)
        netwatch_items = _parse_ros_detail_blocks(netwatch_text)
        nat_items = _parse_ros_detail_blocks(nat_text)
        ether_items = _parse_ros_detail_blocks(ether_text)

        # Build WAN candidates
        wan_candidates = []
        seen_gw = set()

        def _add_candidate(gw_val: str, label: str, ctype: str, distance: int = 1, running: bool = True, iface: str = ""):
            gw_clean = (gw_val or "").strip()
            if not gw_clean or gw_clean in seen_gw or gw_clean.startswith("*"):
                return
            seen_gw.add(gw_clean)
            wan_candidates.append({
                "gateway": gw_clean,
                "label": label,
                "type": ctype,
                "distance": distance,
                "running": running,
                "interface": iface or gw_clean,
            })

        # 1. PPPoE Clients
        for p in pppoe_items:
            name = p.get("name", "")
            iface = p.get("interface", "")
            flags = p.get("_flags", "")
            disabled = "X" in flags or p.get("disabled") == "yes"
            running = "R" in flags and not disabled
            dist_str = p.get("default-route-distance", "1")
            dist = int(dist_str) if str(dist_str).isdigit() else 1
            add_def = p.get("add-default-route", "no")
            status_lbl = "ONLINE (R)" if running else ("DESATIVADO" if disabled else "CONECTANDO")
            _add_candidate(
                name,
                f"{name} [PPPoE sobre {iface} • {status_lbl} • add-default-route={add_def}]",
                "pppoe",
                distance=dist,
                running=running,
                iface=name,
            )

        # 2. DHCP Clients
        for d in dhcp_items:
            iface = d.get("interface", "")
            gw = d.get("gateway", "").split(",")[0].strip()
            addr = d.get("address", "")
            status = d.get("status", "")
            flags = d.get("_flags", "")
            disabled = "X" in flags or d.get("disabled") == "yes"
            dist_str = d.get("default-route-distance", "1")
            dist = int(dist_str) if str(dist_str).isdigit() else 1
            target_gw = gw if gw else iface
            _add_candidate(
                target_gw,
                f"{target_gw} [DHCP em {iface} • IP: {addr or '-'} • {status or ('inativo' if disabled else 'ativo')}]",
                "dhcp",
                distance=dist,
                running=(status == "bound" and not disabled),
                iface=iface,
            )

        # 3. Existing Default Routes (0.0.0.0/0)
        default_routes = []
        monitor_routes = []
        principal_gw = ""
        backup_gw = ""
        principal_dist = 1
        backup_dist = 2
        host1_detected = ""
        host2_detected = ""

        for r in route_items:
            dst = r.get("dst-address", "")
            gw = r.get("gateway", "").split(",")[0].strip()
            comm = r.get("comment", "").strip()
            comm_upper = comm.upper()
            flags = r.get("_flags", "")
            dist_str = r.get("distance", "1")
            dist = int(dist_str) if str(dist_str).isdigit() else 1
            is_blackhole = "b" in flags.lower() or "blackhole" in r or r.get("type") == "blackhole"

            if dst == "0.0.0.0/0":
                default_routes.append({
                    "dst_address": dst,
                    "gateway": gw,
                    "distance": dist,
                    "comment": comm,
                    "flags": flags,
                    "active": "A" in flags,
                    "disabled": "X" in flags or r.get("disabled") == "yes",
                    "dynamic": "D" in flags,
                })
                if gw and not is_blackhole:
                    _add_candidate(
                        gw,
                        f"{gw} [Rota Padrão Atual • dist={dist} • comment={comm or '-'} • flags={flags}]",
                        "route",
                        distance=dist,
                        running="A" in flags,
                        iface=gw,
                    )
                if comm_upper in ("PRINCIPAL", "LINK PRINCIPAL", "ROTA-LINK1") or "PESO 1" in comm_upper:
                    principal_gw = gw
                    principal_dist = dist
                elif comm_upper in ("BACKUP", "LINK SECUNDARIO", "LINK BACKUP", "ROTA-LINK2") or "PESO 2" in comm_upper:
                    backup_gw = gw
                    backup_dist = dist
            elif (dst.endswith("/32") and not ("D" in flags and "C" in flags)) or comm_upper in (
                "PRINCIPAL",
                "BACKUP",
                "MONITOR-PRINCIPAL",
                "MONITOR-BACKUP",
                "BLACKHOLE-MONITOR-PRINCIPAL",
                "BLACKHOLE-MONITOR-BACKUP",
            ) or "MONITOR" in comm_upper:
                host_ip = dst.split("/")[0].strip()
                monitor_routes.append({
                    "dst_address": dst,
                    "gateway": "BLACKHOLE" if is_blackhole else gw,
                    "distance": dist,
                    "comment": comm,
                    "flags": flags,
                    "active": "A" in flags,
                    "disabled": "X" in flags or r.get("disabled") == "yes",
                })
                if not is_blackhole:
                    if comm_upper in ("MONITOR-PRINCIPAL", "PRINCIPAL") or "PRINCIPAL" in comm_upper or "LINK1" in comm_upper:
                        if host_ip and host_ip != "0.0.0.0":
                            host1_detected = host_ip
                        if gw and not principal_gw:
                            principal_gw = gw
                    elif comm_upper in ("MONITOR-BACKUP", "BACKUP") or "BACKUP" in comm_upper or "LINK2" in comm_upper:
                        if host_ip and host_ip != "0.0.0.0":
                            host2_detected = host_ip
                        if gw and not backup_gw:
                            backup_gw = gw

        # 4. Masquerade NAT interfaces
        for n in nat_items:
            if n.get("action") == "masquerade":
                out_if = n.get("out-interface", "")
                if out_if and not out_if.startswith("*"):
                    _add_candidate(
                        out_if,
                        f"{out_if} [Interface com NAT Masquerade ({n.get('comment') or 'srcnat'})]",
                        "nat",
                        distance=2,
                        running=True,
                        iface=out_if,
                    )

        # 5. Ethernet interfaces (fallback options)
        for e in ether_items:
            ename = e.get("name", "")
            flags = e.get("_flags", "")
            if ename:
                _add_candidate(
                    ename,
                    f"{ename} [Interface Ethernet ({'R' if 'R' in flags else 'down'})]",
                    "ethernet",
                    distance=3,
                    running="R" in flags,
                    iface=ename,
                )

        # 6. Netwatch entries
        netwatch_summary = []
        for nw in netwatch_items:
            comm = nw.get("comment", "").strip()
            host = nw.get("host", "").strip()
            status = nw.get("status", "unknown")
            interval = nw.get("interval", "10s")
            nw_type = nw.get("type", "simple")
            flags = nw.get("_flags", "")
            disabled = "X" in flags or nw.get("disabled") == "yes"
            up_s = nw.get("up-script", "")
            down_s = nw.get("down-script", "")
            has_tg = "failover-event" in (up_s + down_s) or "api.telegram.org" in (up_s + down_s)

            netwatch_summary.append({
                "comment": comm,
                "host": host,
                "status": "disabled" if disabled else status,
                "interval": interval,
                "type": nw_type,
                "disabled": disabled,
                "has_telegram": has_tg,
            })
            comm_up = comm.upper()
            if "PRINCIPAL" in comm_up or "LINK 1" in comm_up:
                if host and not host1_detected:
                    host1_detected = host
            elif "BACKUP" in comm_up or "SECUNDARIO" in comm_up or "LINK 2" in comm_up:
                if host and not host2_detected:
                    host2_detected = host

        # Auto-pick Link 1 and Link 2 if not explicitly tagged by comments yet
        non_ether_candidates = [c for c in wan_candidates if c["type"] in ("pppoe", "dhcp", "route", "nat")]
        sorted_cands = sorted(non_ether_candidates, key=lambda x: (x["distance"], 0 if x["running"] else 1))

        if not principal_gw and len(sorted_cands) >= 1:
            principal_gw = sorted_cands[0]["gateway"]
        if not backup_gw:
            for c in sorted_cands:
                if c["gateway"] != principal_gw:
                    backup_gw = c["gateway"]
                    break

        is_configured = any(
            r["comment"].upper() in ("PRINCIPAL", "LINK PRINCIPAL") for r in default_routes
        ) and len(netwatch_summary) > 0

        # Build human-readable terminal report
        report_lines = [
            f"=== ANÁLISE DE FAILOVER & LINKS WAN ({identity or ip}) ===",
            f"RouterOS: {info.get('ros_version_detail') or ros_ver} ({ros_ver.upper()}) | Modelo: {info.get('board_name') or '-'}",
            f"Status do Failover: {'CONFIGURADO' if is_configured else 'NÃO PADRONIZADO / PENDENTE'}",
            "",
            "--- Candidatos de Link WAN Detectados ---",
        ]
        if non_ether_candidates:
            for idx, c in enumerate(non_ether_candidates, 1):
                report_lines.append(f"  {idx}. {c['label']}")
        else:
            report_lines.append("  (Nenhuma interface PPPoE/DHCP/Rota padrão detectada)")

        report_lines.append("\n--- Rotas Padrão (0.0.0.0/0) Atuais ---")
        if default_routes:
            for r in default_routes:
                report_lines.append(
                    f"  [{r['flags'] or '-'}] dst=0.0.0.0/0 gw={r['gateway']} dist={r['distance']} comment=\"{r['comment']}\""
                )
        else:
            report_lines.append("  (Nenhuma rota 0.0.0.0/0 encontrada)")

        report_lines.append("\n--- Rotas de Monitoramento (/32 & Blackhole) ---")
        if monitor_routes:
            for r in monitor_routes:
                report_lines.append(
                    f"  [{r['flags'] or '-'}] dst={r['dst_address']} gw={r['gateway']} dist={r['distance']} comment=\"{r['comment']}\""
                )
        else:
            report_lines.append("  (Nenhuma rota /32 de monitoramento configurada)")

        report_lines.append("\n--- Regras de Netwatch (/tool netwatch) ---")
        if netwatch_summary:
            for nw in netwatch_summary:
                tg_tag = " [Telegram Webhook OK]" if nw["has_telegram"] else " [Sem Webhook Telegram]"
                report_lines.append(
                    f"  • {nw['comment'] or nw['host']}: host={nw['host']} status={nw['status'].upper()} interval={nw['interval']} type={nw['type']}{tg_tag}"
                )
        else:
            report_lines.append("  (Nenhuma regra no /tool netwatch)")

        report_lines.extend([
            "",
            "--- Sugestão Preenchida para a Etapa 2 (Configurar) ---",
            f"  • Link 1 (PRINCIPAL): gateway={principal_gw or '(selecione)'} | Ping Externo={host1_detected or '198.41.0.4'} | Distância={principal_dist}",
            f"  • Link 2 (BACKUP):    gateway={backup_gw or '(selecione)'} | Ping Externo={host2_detected or '199.9.14.201'} | Distância={backup_dist}",
        ])

        analysis = {
            "ros_version": ros_ver,
            "ros_version_detail": info.get("ros_version_detail") or ros_ver,
            "board_name": info.get("board_name") or "",
            "identity": identity,
            "is_configured": is_configured,
            "wan_candidates": wan_candidates,
            "default_routes": default_routes,
            "monitor_routes": monitor_routes,
            "netwatch": netwatch_summary,
            "suggested": {
                "link1_gateway": principal_gw,
                "link1_host": host1_detected or "198.41.0.4",
                "link1_distance": principal_dist,
                "link2_gateway": backup_gw,
                "link2_host": host2_detected or "199.9.14.201",
                "link2_distance": backup_dist,
                "interval": netwatch_summary[0]["interval"] if netwatch_summary else "10s",
            },
            "terminal_report": "\n".join(report_lines),
            "info": info,
        }
        return True, analysis, "Análise de links, rotas e Netwatch concluída com sucesso!"
    except Exception as e:
        return False, {}, f"Erro SSH ao analisar failover: {e}"
    finally:
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass


async def analyze_device_failover(dev: dict, client_ip: str = "") -> dict:
    if not dev.get("ssh_enabled"):
        return {"ok": False, "error": "O acesso remoto SSH está desabilitado para este dispositivo."}

    password_plain = decrypt_secret(dev["ssh_password"])
    if not dev.get("ssh_username") or not password_plain:
        return {"ok": False, "error": "Credenciais SSH (usuário/senha) não cadastradas para este dispositivo."}

    t0 = time.monotonic()
    async with SSH_SEMAPHORE:
        loop = asyncio.get_running_loop()
        ok, analysis, msg = await loop.run_in_executor(
            None,
            _analyze_failover_ssh_sync,
            dev["ip"],
            dev["ssh_port"],
            dev["ssh_username"],
            password_plain,
            dev.get("ros_version") or "auto",
        )
    duration_ms = int((time.monotonic() - t0) * 1000)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    try:
        c = conn.cursor()
        info = analysis.get("info") or {}
        if ok and info:
            c.execute(
                """
                UPDATE devices
                SET ros_version = COALESCE(NULLIF(?, 'auto'), ros_version),
                    ros_version_detail = COALESCE(NULLIF(?, ''), ros_version_detail),
                    board_name = COALESCE(NULLIF(?, ''), board_name),
                    architecture = COALESCE(NULLIF(?, ''), architecture),
                    uptime_str = COALESCE(NULLIF(?, ''), uptime_str),
                    cpu_load = COALESCE(?, cpu_load),
                    memory_total_mb = COALESCE(?, memory_total_mb),
                    memory_used_mb = COALESCE(?, memory_used_mb),
                    memory_used_pct = COALESCE(?, memory_used_pct),
                    ssh_host_key = COALESCE(NULLIF(?, ''), ssh_host_key)
                WHERE id = ?
                """,
                (
                    info.get("ros_version"),
                    info.get("ros_version_detail"),
                    info.get("board_name"),
                    info.get("architecture"),
                    info.get("uptime_str"),
                    info.get("cpu_load"),
                    info.get("memory_total_mb"),
                    info.get("memory_used_mb"),
                    info.get("memory_used_pct"),
                    info.get("ssh_host_key"),
                    dev["id"],
                ),
            )
        preview = (analysis.get("terminal_report") if ok else msg)[:2000]
        c.execute(
            """
            INSERT INTO command_logs (
                device_id, device_name, device_ip, action_key, command_executed,
                status, output_preview, duration_ms, client_ip, created_at
            ) VALUES (?, ?, ?, 'failover_analyze', '/ip route print; /tool netwatch print (Análise Failover)', ?, ?, ?, ?, ?)
            """,
            (
                dev["id"],
                dev["name"],
                dev["ip"],
                "SUCCESS" if ok else "ERROR",
                preview,
                duration_ms,
                client_ip,
                now,
            ),
        )
        prune_command_logs(c, 200)
        conn.commit()
    finally:
        conn.close()

    if not ok:
        return {"ok": False, "error": msg}

    analysis.pop("info", None)
    return {
        "ok": True,
        "message": msg,
        "duration_ms": duration_ms,
        "timestamp": now,
        "analysis": analysis,
    }


def _configure_failover_ssh_sync(
    dev_id: int,
    ip: str,
    port: int,
    username: str,
    password_plain: str,
    known_ros_version: str,
    cfg: dict,
) -> tuple[bool, str, str, dict]:
    """
    Applies the Failover + External Ping Routes + Netwatch + Telegram Webhook configuration
    via SSH on RouterOS v6 or v7 without interrupting the active SSH session.
    """
    ssh = None
    try:
        ssh = _connect_ssh(ip, port, username, password_plain, timeout=14)
        fingerprint = _get_host_key_fingerprint(ssh)
        _, res_out, _ = _exec_ssh_cmd(ssh, "/system resource print without-paging", timeout=10)
        info = _parse_resource_output(res_out)
        info["ssh_host_key"] = fingerprint
        ros_ver = (
            info["ros_version"]
            if info["ros_version"] in ("v6", "v7")
            else (known_ros_version if known_ros_version in ("v6", "v7") else "v6")
        )
        info["ros_version"] = ros_ver

        link1_gw = cfg["link1_gateway"]
        link2_gw = cfg["link2_gateway"]
        host1 = cfg["link1_host"]
        host2 = cfg["link2_host"]
        dist1 = int(cfg["link1_distance"])
        dist2 = int(cfg["link2_distance"])
        interval = cfg["interval"]

        steps_log = []

        # 1. Ensure DNS servers and static DNS for bkp.jeffgsan.com.br (for Telegram webhook via /tool fetch)
        _, dns_out, _ = _exec_ssh_cmd(ssh, "/ip dns print without-paging", timeout=8)
        if "servers: \n" in dns_out or re.search(r"servers:\s*$", dns_out, re.MULTILINE):
            _exec_ssh_cmd(ssh, "/ip dns set servers=8.8.8.8,1.1.1.1", timeout=8)
            steps_log.append("• DNS configurado com 8.8.8.8, 1.1.1.1")

        _exec_ssh_cmd(ssh, '/ip dns static remove [find comment="BKPProvider Failover"]', timeout=8)
        _exec_ssh_cmd(ssh, '/ip dns static remove [find name="bkp.jeffgsan.com.br"]', timeout=8)
        _exec_ssh_cmd(
            ssh,
            f'/ip dns static add name=bkp.jeffgsan.com.br address={FAILOVER_SERVER_IP} comment="BKPProvider Failover"',
            timeout=8,
        )
        steps_log.append(f"• DNS estático bkp.jeffgsan.com.br -> {FAILOVER_SERVER_IP} configurado para disparo Telegram")

        # 2. Configure /ip route (Link 1 PRINCIPAL, Link 2 BACKUP, /32 Monitors & Blackhole dist=250)
        _, dhcp_out, _ = _exec_ssh_cmd(ssh, "/ip dhcp-client print detail without-paging", timeout=8)
        dhcp_entries = _parse_ros_detail_blocks(dhcp_out)
        dhcp_by_iface = {d.get("interface", ""): d for d in dhcp_entries if d.get("interface")}

        resolved_gw1 = link1_gw
        if link1_gw in dhcp_by_iface and dhcp_by_iface[link1_gw].get("gateway"):
            resolved_gw1 = dhcp_by_iface[link1_gw]["gateway"].split(",")[0].strip()
            steps_log.append(f"• Gateway DHCP do Link 1 ({link1_gw}) resolvido para IP {resolved_gw1}")

        resolved_gw2 = link2_gw
        if link2_gw and link2_gw in dhcp_by_iface and dhcp_by_iface[link2_gw].get("gateway"):
            resolved_gw2 = dhcp_by_iface[link2_gw]["gateway"].split(",")[0].strip()
            steps_log.append(f"• Gateway DHCP do Link 2 ({link2_gw}) resolvido para IP {resolved_gw2}")

        q_gw1 = _quote_ros_val(resolved_gw1)
        q_gw2 = _quote_ros_val(resolved_gw2) if resolved_gw2 else ""

        # Step 2a: Add new default routes FIRST with temporary comments so the router NEVER loses its default route
        _exec_ssh_cmd(ssh, '/ip route remove [find comment="PRINCIPAL_NEW"]; /ip route remove [find comment="BACKUP_NEW"]', timeout=8)
        _exec_ssh_cmd(
            ssh,
            f'/ip route add dst-address=0.0.0.0/0 gateway={q_gw1} distance={dist1} disabled=no comment="PRINCIPAL_NEW"',
            timeout=10,
        )
        if q_gw2:
            _exec_ssh_cmd(
                ssh,
                f'/ip route add dst-address=0.0.0.0/0 gateway={q_gw2} distance={dist2} disabled=no comment="BACKUP_NEW"',
                timeout=10,
            )

        # Remove old PRINCIPAL / BACKUP routes and rename _NEW -> PRINCIPAL / BACKUP atomically
        swap_cmd = (
            '/ip route remove [find comment="PRINCIPAL"]; '
            '/ip route remove [find comment="LINK PRINCIPAL"]; '
            '/ip route set [find comment="PRINCIPAL_NEW"] comment="PRINCIPAL"'
        )
        if q_gw2:
            swap_cmd += (
                '; /ip route remove [find comment="BACKUP"]; '
                '/ip route remove [find comment="LINK SECUNDARIO"]; '
                '/ip route set [find comment="BACKUP_NEW"] comment="BACKUP"'
            )
        _exec_ssh_cmd(ssh, swap_cmd, timeout=10)
        steps_log.append(f"• Rota padrão Link 1 criada: dst-address=0.0.0.0/0 gateway={resolved_gw1} distance={dist1} comment=PRINCIPAL")
        if resolved_gw2:
            steps_log.append(f"• Rota padrão Link 2 criada: dst-address=0.0.0.0/0 gateway={resolved_gw2} distance={dist2} comment=BACKUP")

        # Step 2b: Clean up old monitor /32 & blackhole routes and create fresh ones
        clean_mon_cmd = (
            '/ip route remove [find comment="MONITOR-PRINCIPAL"]; '
            '/ip route remove [find comment="MONITOR-BACKUP"]; '
            '/ip route remove [find comment="BLACKHOLE-MONITOR-PRINCIPAL"]; '
            '/ip route remove [find comment="BLACKHOLE-MONITOR-BACKUP"]; '
            f'/ip route remove [find dst-address="{host1}/32"]; '
            f'/ip route remove [find dst-address="{host2}/32"]'
        )
        _exec_ssh_cmd(ssh, clean_mon_cmd, timeout=10)

        # Create MONITOR-PRINCIPAL (/32 route via Link 1)
        is_ip_gw1 = bool(_IPV4_RE.match(resolved_gw1))
        if ros_ver == "v7" and not is_ip_gw1:
            _, out_m1, err_m1 = _exec_ssh_cmd(
                ssh,
                f'/ip route add comment="MONITOR-PRINCIPAL" disabled=no distance=1 dst-address={host1}/32 gateway={q_gw1} routing-table=main scope=30 target-scope=10 vrf-interface={q_gw1}',
                timeout=10,
            )
            if err_m1 or "invalid" in out_m1.lower() or "expected" in out_m1.lower() or "failure" in out_m1.lower():
                _exec_ssh_cmd(
                    ssh,
                    f'/ip route add comment="MONITOR-PRINCIPAL" disabled=no distance=1 dst-address={host1}/32 gateway={q_gw1} scope=30 target-scope=10',
                    timeout=10,
                )
        else:
            _exec_ssh_cmd(
                ssh,
                f'/ip route add comment="MONITOR-PRINCIPAL" disabled=no distance=1 dst-address={host1}/32 gateway={q_gw1} scope=30 target-scope=10',
                timeout=10,
            )
        steps_log.append(f"• Rota de monitoramento Link 1 criada: dst-address={host1}/32 gateway={resolved_gw1} comment=MONITOR-PRINCIPAL")

        # Create MONITOR-BACKUP (/32 route via Link 2)
        if resolved_gw2:
            is_ip_gw2 = bool(_IPV4_RE.match(resolved_gw2))
            if ros_ver == "v7" and not is_ip_gw2:
                _, out_m2, err_m2 = _exec_ssh_cmd(
                    ssh,
                    f'/ip route add comment="MONITOR-BACKUP" disabled=no distance=1 dst-address={host2}/32 gateway={q_gw2} routing-table=main scope=30 target-scope=10 vrf-interface={q_gw2}',
                    timeout=10,
                )
                if err_m2 or "invalid" in out_m2.lower() or "expected" in out_m2.lower() or "failure" in out_m2.lower():
                    _exec_ssh_cmd(
                        ssh,
                        f'/ip route add comment="MONITOR-BACKUP" disabled=no distance=1 dst-address={host2}/32 gateway={q_gw2} scope=30 target-scope=10',
                        timeout=10,
                    )
            else:
                _exec_ssh_cmd(
                    ssh,
                    f'/ip route add comment="MONITOR-BACKUP" disabled=no distance=1 dst-address={host2}/32 gateway={q_gw2} scope=30 target-scope=10',
                    timeout=10,
                )
            steps_log.append(f"• Rota de monitoramento Link 2 criada: dst-address={host2}/32 gateway={resolved_gw2} comment=MONITOR-BACKUP")

        # Step 2c: Standard Blackhole routes at distance 250 (Balaio pattern) so pings never leak through the other link
        if ros_ver == "v7":
            _exec_ssh_cmd(
                ssh,
                f'/ip route add blackhole comment="BLACKHOLE-MONITOR-PRINCIPAL" disabled=no distance=250 dst-address={host1}/32',
                timeout=8,
            )
            if resolved_gw2:
                _exec_ssh_cmd(
                    ssh,
                    f'/ip route add blackhole comment="BLACKHOLE-MONITOR-BACKUP" disabled=no distance=250 dst-address={host2}/32',
                    timeout=8,
                )
        else:
            _exec_ssh_cmd(
                ssh,
                f'/ip route add type=blackhole comment="BLACKHOLE-MONITOR-PRINCIPAL" disabled=no distance=250 dst-address={host1}/32',
                timeout=8,
            )
            if resolved_gw2:
                _exec_ssh_cmd(
                    ssh,
                    f'/ip route add type=blackhole comment="BLACKHOLE-MONITOR-BACKUP" disabled=no distance=250 dst-address={host2}/32',
                    timeout=8,
                )
        steps_log.append(f"• Rotas Blackhole (dist=250) adicionadas para {host1}/32" + (f" e {host2}/32" if resolved_gw2 else ""))

        # 3. Configure /tool netwatch (v7 standard Balaio ICMP probe & v6 standard Netwatch + Telegram alert)
        token = generate_device_webhook_token(dev_id)
        url_p_down = f"{FAILOVER_WEBHOOK_BASE_URL}/api/license/failover-event/{dev_id}/PRINCIPAL/DOWN/{token}"
        url_p_up = f"{FAILOVER_WEBHOOK_BASE_URL}/api/license/failover-event/{dev_id}/PRINCIPAL/UP/{token}"
        url_b_down = f"{FAILOVER_WEBHOOK_BASE_URL}/api/license/failover-event/{dev_id}/BACKUP/DOWN/{token}"
        url_b_up = f"{FAILOVER_WEBHOOK_BASE_URL}/api/license/failover-event/{dev_id}/BACKUP/UP/{token}"

        down_script_1 = (
            '/ip route disable [find comment=PRINCIPAL]\\r\\n'
            '/log error message=\\"O LINK PRINCIPAL CAIU\\"\\r\\n'
            f':delay 2s\\r\\n:do {{ /tool fetch url=\\"{url_p_down}\\" keep-result=no }} on-error={{}}'
        )
        up_script_1 = (
            '/ip route enable [find comment=PRINCIPAL]\\r\\n'
            '/log error message=\\"O LINK PRINCIPAL VOLTOU\\"\\r\\n'
            f':delay 2s\\r\\n:do {{ /tool fetch url=\\"{url_p_up}\\" keep-result=no }} on-error={{}}'
        )
        down_script_2 = (
            '/ip route disable [find comment=BACKUP]\\r\\n'
            '/log error message=\\"O LINK DE BACKUP FOI INATIVADO\\"\\r\\n'
            f':delay 2s\\r\\n:do {{ /tool fetch url=\\"{url_b_down}\\" keep-result=no }} on-error={{}}'
        )
        up_script_2 = (
            '/ip route enable [find comment=BACKUP]\\r\\n'
            '/log error message=\\"LINK BACKUP ATIVO\\"\\r\\n'
            f':delay 2s\\r\\n:do {{ /tool fetch url=\\"{url_b_up}\\" keep-result=no }} on-error={{}}'
        )

        # Remove existing Netwatch rules for Principal / Backup
        _exec_ssh_cmd(
            ssh,
            (
                '/tool netwatch remove [find comment="Monitora Link Principal"]; '
                '/tool netwatch remove [find comment="MONITOR LINK PRINCIPAL"]; '
                '/tool netwatch remove [find comment="Monitora Link de Backup"]; '
                f'/tool netwatch remove [find host={host1}]; '
                + (f'/tool netwatch remove [find host={host2}]' if link2_gw else "")
            ),
            timeout=10,
        )

        if ros_ver == "v7":
            # Try v7 advanced ICMP probe (BALAIO reference) first, fallback to type=simple if older v7
            nw1_v7_icmp = (
                f'/tool netwatch add comment="Monitora Link Principal" disabled=no host={host1} interval={interval} '
                f'packet-count=5 packet-interval=500ms thr-avg=1s thr-jitter=2s thr-loss-percent=80% thr-max=2s thr-stdev=1s '
                f'type=icmp down-script="{down_script_1}" up-script="{up_script_1}"'
            )
            _, nw1_out, nw1_err = _exec_ssh_cmd(ssh, nw1_v7_icmp, timeout=10)
            if nw1_err or "expected" in nw1_out.lower() or "invalid" in nw1_out.lower() or "failure" in nw1_out.lower():
                nw1_v7_simple = (
                    f'/tool netwatch add comment="Monitora Link Principal" disabled=no host={host1} interval={interval} '
                    f'type=simple down-script="{down_script_1}" up-script="{up_script_1}"'
                )
                _exec_ssh_cmd(ssh, nw1_v7_simple, timeout=10)
                steps_log.append(f"• Netwatch v7 (type=simple) criado para Link Principal ({host1}, intervalo {interval})")
            else:
                steps_log.append(f"• Netwatch v7 (type=icmp avançado padrão Balaio) criado para Link Principal ({host1}, intervalo {interval})")

            if link2_gw:
                nw2_v7_icmp = (
                    f'/tool netwatch add comment="Monitora Link de Backup" disabled=no host={host2} interval={interval} '
                    f'packet-count=5 packet-interval=500ms thr-avg=1s thr-jitter=2s thr-loss-percent=80% thr-max=2s thr-stdev=1s '
                    f'type=icmp down-script="{down_script_2}" up-script="{up_script_2}"'
                )
                _, nw2_out, nw2_err = _exec_ssh_cmd(ssh, nw2_v7_icmp, timeout=10)
                if nw2_err or "expected" in nw2_out.lower() or "invalid" in nw2_out.lower() or "failure" in nw2_out.lower():
                    nw2_v7_simple = (
                        f'/tool netwatch add comment="Monitora Link de Backup" disabled=no host={host2} interval={interval} '
                        f'type=simple down-script="{down_script_2}" up-script="{up_script_2}"'
                    )
                    _exec_ssh_cmd(ssh, nw2_v7_simple, timeout=10)
                steps_log.append(f"• Netwatch v7 criado para Link de Backup ({host2}, intervalo {interval})")
        else:
            # RouterOS v6 simple & clean Netwatch
            nw1_v6 = (
                f'/tool netwatch add comment="Monitora Link Principal" disabled=no host={host1} interval={interval} '
                f'timeout=2s down-script="{down_script_1}" up-script="{up_script_1}"'
            )
            _exec_ssh_cmd(ssh, nw1_v6, timeout=10)
            steps_log.append(f"• Netwatch v6 ativado para Link Principal ({host1}, intervalo {interval})")

            if link2_gw:
                nw2_v6 = (
                    f'/tool netwatch add comment="Monitora Link de Backup" disabled=no host={host2} interval={interval} '
                    f'timeout=2s down-script="{down_script_2}" up-script="{up_script_2}"'
                )
                _exec_ssh_cmd(ssh, nw2_v6, timeout=10)
                steps_log.append(f"• Netwatch v6 ativado para Link de Backup ({host2}, intervalo {interval})")

        # 4. Fetch final state for verification in terminal
        _, verify_out, _ = _exec_ssh_cmd(
            ssh,
            ':put "=== ROTAS CONFIGURADAS ==="; /ip route print detail without-paging; :put "\n=== NETWATCH CONFIGURADO ==="; /tool netwatch print detail without-paging',
            timeout=12,
        )

        summary_header = "\n".join([
            f"=== FAILOVER CONFIGURADO COM SUCESSO ({info.get('ros_version_detail') or ros_ver}) ===",
            *steps_log,
            "",
            verify_out.strip(),
        ])
        return True, "Failover e Netwatch configurados com sucesso!", summary_header, info
    except Exception as e:
        return False, f"Falha ao configurar failover via SSH: {e}", str(e), {}
    finally:
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass


async def configure_device_failover(dev: dict, payload: dict, client_ip: str = "") -> dict:
    if not dev.get("ssh_enabled"):
        return {"ok": False, "error": "O acesso remoto SSH está desabilitado para este dispositivo."}

    password_plain = decrypt_secret(dev["ssh_password"])
    if not dev.get("ssh_username") or not password_plain:
        return {"ok": False, "error": "Credenciais SSH (usuário/senha) não cadastradas para este dispositivo."}

    link1_gw = (payload.get("link1_gateway") or "").strip()
    link2_gw = (payload.get("link2_gateway") or "").strip()
    host1 = (payload.get("link1_host") or "198.41.0.4").strip()
    host2 = (payload.get("link2_host") or "199.9.14.201").strip()
    dist1 = int(payload.get("link1_distance") or 1)
    dist2 = int(payload.get("link2_distance") or 2)
    interval = (payload.get("interval") or "10s").strip()

    if not link1_gw or not _SAFE_GW_RE.match(link1_gw):
        return {"ok": False, "error": "Informe um Gateway ou Interface válido para o Link 1 (Principal)."}
    if link2_gw and not _SAFE_GW_RE.match(link2_gw):
        return {"ok": False, "error": "Gateway ou Interface do Link 2 (Backup) contém caracteres inválidos."}
    if not _IPV4_RE.match(host1):
        return {"ok": False, "error": "Informe um IP externo IPv4 válido para o ping do Link 1 (ex: 198.41.0.4)."}
    if link2_gw and not _IPV4_RE.match(host2):
        return {"ok": False, "error": "Informe um IP externo IPv4 válido para o ping do Link 2 (ex: 199.9.14.201)."}
    if not _SAFE_INTERVAL_RE.match(interval):
        return {"ok": False, "error": "Intervalo do Netwatch inválido (use ex: 10s, 15s, 30s, 1m)."}

    cfg = {
        "link1_gateway": link1_gw,
        "link2_gateway": link2_gw,
        "link1_host": host1,
        "link2_host": host2,
        "link1_distance": max(1, min(dist1, 240)),
        "link2_distance": max(1, min(dist2, 245)),
        "interval": interval,
    }

    # Set grace window BEFORE executing SSH so initial Netwatch UP probes during setup don't trigger false recovery alerts
    _FAILOVER_SETUP_GRACE[dev["id"]] = time.monotonic()

    t0 = time.monotonic()
    async with SSH_SEMAPHORE:
        loop = asyncio.get_running_loop()
        ok, msg, output, info = await loop.run_in_executor(
            None,
            _configure_failover_ssh_sync,
            dev["id"],
            dev["ip"],
            dev["ssh_port"],
            dev["ssh_username"],
            password_plain,
            dev.get("ros_version") or "auto",
            cfg,
        )
    duration_ms = int((time.monotonic() - t0) * 1000)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _FAILOVER_SETUP_GRACE[dev["id"]] = time.monotonic()

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO command_logs (
                device_id, device_name, device_ip, action_key, command_executed,
                status, output_preview, duration_ms, client_ip, created_at
            ) VALUES (?, ?, ?, 'failover_configure', ?, ?, ?, ?, ?, ?)
            """,
            (
                dev["id"],
                dev["name"],
                dev["ip"],
                f"Failover: L1={link1_gw}->{host1} | L2={link2_gw or '-'}->{host2}",
                "SUCCESS" if ok else "ERROR",
                (output or msg)[:2000],
                duration_ms,
                client_ip,
                now,
            ),
        )
        prune_command_logs(c, 200)
        conn.commit()
    finally:
        conn.close()

    if ok:
        dest_id = dev["telegram_destination_id"] if "telegram_destination_id" in dev.keys() else None
        ros_lbl = info.get("ros_version_detail") or dev.get("ros_version_detail") or dev.get("ros_version") or "RouterOS"
        tg_text = (
            f"🛡️ <b>[Failover & Netwatch Configurado]</b>\n"
            f"Equipamento: <b>{dev['name']}</b> (<code>{dev['ip']}</code> — {ros_lbl})\n"
            f"• <b>Link 1 (PRINCIPAL):</b> <code>{link1_gw or 'atual'}</code> ➔ Ping <code>{host1}</code> (dist={cfg['link1_distance']})\n"
            + (
                f"• <b>Link 2 (BACKUP):</b> <code>{link2_gw}</code> ➔ Ping <code>{host2}</code> (dist={cfg['link2_distance']})\n"
                if link2_gw
                else ""
            )
            + f"• <b>Netwatch:</b> Ativo (intervalo <code>{interval}</code>) com alerta automático no Telegram em caso de troca de link."
        )
        await send_telegram(tg_text, dest_id)

    if not ok:
        return {"ok": False, "error": msg, "output": output}

    return {
        "ok": True,
        "message": msg,
        "output": output,
        "duration_ms": duration_ms,
        "timestamp": now,
    }


def _toggle_netwatch_ssh_sync(
    ip: str,
    port: int,
    username: str,
    password_plain: str,
    enable: bool,
) -> tuple[bool, str, str]:
    ssh = None
    try:
        ssh = _connect_ssh(ip, port, username, password_plain, timeout=10)
        act = "enable" if enable else "disable"
        cmd = (
            f'/tool netwatch {act} [find comment="Monitora Link Principal"]; '
            f'/tool netwatch {act} [find comment="MONITOR LINK PRINCIPAL"]; '
            f'/tool netwatch {act} [find comment="Monitora Link de Backup"]; '
            '/tool netwatch print detail without-paging'
        )
        _, out, _ = _exec_ssh_cmd(ssh, cmd, timeout=10)
        state_lbl = "ATIVADO" if enable else "PAUSADO"
        return True, f"Netwatch de Failover {state_lbl} com sucesso!", out
    except Exception as e:
        return False, f"Erro SSH ao alternar Netwatch: {e}", str(e)
    finally:
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass


async def toggle_device_failover_netwatch(dev: dict, enable: bool, client_ip: str = "") -> dict:
    if not dev.get("ssh_enabled"):
        return {"ok": False, "error": "O acesso remoto SSH está desabilitado para este dispositivo."}

    password_plain = decrypt_secret(dev["ssh_password"])
    if not dev.get("ssh_username") or not password_plain:
        return {"ok": False, "error": "Credenciais SSH não cadastradas para este dispositivo."}

    if enable:
        _FAILOVER_SETUP_GRACE[dev["id"]] = time.monotonic()

    t0 = time.monotonic()
    async with SSH_SEMAPHORE:
        loop = asyncio.get_running_loop()
        ok, msg, out = await loop.run_in_executor(
            None,
            _toggle_netwatch_ssh_sync,
            dev["ip"],
            dev["ssh_port"],
            dev["ssh_username"],
            password_plain,
            enable,
        )
    duration_ms = int((time.monotonic() - t0) * 1000)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO command_logs (
                device_id, device_name, device_ip, action_key, command_executed,
                status, output_preview, duration_ms, client_ip, created_at
            ) VALUES (?, ?, ?, 'failover_netwatch_toggle', ?, ?, ?, ?, ?, ?)
            """,
            (
                dev["id"],
                dev["name"],
                dev["ip"],
                f"/tool netwatch {'enable' if enable else 'disable'} (Failover)",
                "SUCCESS" if ok else "ERROR",
                (out or msg)[:2000],
                duration_ms,
                client_ip,
                now,
            ),
        )
        prune_command_logs(c, 200)
        conn.commit()
    finally:
        conn.close()

    if not ok:
        return {"ok": False, "error": msg}

    return {"ok": True, "message": msg, "output": out, "duration_ms": duration_ms, "timestamp": now}


async def handle_failover_webhook_event(
    device_id: int,
    link_role: str,
    state: str,
    token: str,
    client_ip: str = "",
) -> dict:
    """
    Receives real-time failover state transitions triggered by MikroTik /tool netwatch
    and dispatches the alert to the device's configured Telegram destination.
    """
    if not verify_device_webhook_token(device_id, token):
        return {"ok": False, "status": "unauthorized", "message": "Token de webhook inválido."}

    role_norm = (link_role or "PRINCIPAL").strip().upper()
    state_norm = (state or "DOWN").strip().upper()
    now_mono = time.monotonic()

    # Check if this is an initial UP probe right after provisioning failover (within 25s grace window)
    setup_ts = _FAILOVER_SETUP_GRACE.get(device_id)
    prev_state_info = _FAILOVER_LAST_EVENT.get((device_id, role_norm))
    if state_norm == "UP" and setup_ts and (now_mono - setup_ts) < 25.0:
        if not prev_state_info or prev_state_info[0] != "DOWN":
            _FAILOVER_LAST_EVENT[(device_id, role_norm)] = ("UP", now_mono)
            return {"ok": True, "status": "initial_up_ignored"}

    # Deduplicate identical consecutive events within 15s
    if prev_state_info:
        last_st, last_ts = prev_state_info
        if last_st == state_norm and (now_mono - last_ts) < 15.0:
            return {"ok": True, "status": "deduplicated"}

    _FAILOVER_LAST_EVENT[(device_id, role_norm)] = (state_norm, now_mono)

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE id=?", (device_id,))
        row = c.fetchone()
        if not row:
            return {"ok": False, "status": "not_found", "message": "Dispositivo não encontrado."}
        dev = dict(row)
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if role_norm == "PRINCIPAL" and state_norm == "DOWN":
            tg_msg = (
                f"🚨 <b>[FAILOVER — LINK PRINCIPAL CAIU]</b>\n"
                f"Dispositivo: <b>{dev['name']}</b> (<code>{dev['ip']}</code>)\n"
                f"Evento: O <b>Link 1 (PRINCIPAL)</b> parou de responder ao ping externo.\n"
                f"Ação: Rota Principal desativada — tráfego comutado automaticamente para o <b>Link 2 (BACKUP)</b>!\n"
                f"Horário: <code>{now_str}</code>"
            )
            log_preview = "O LINK PRINCIPAL CAIU -> Rota Principal desativada, operando no Link Backup (Alerta Telegram enviado)"
        elif role_norm == "PRINCIPAL" and state_norm == "UP":
            tg_msg = (
                f"🟢 <b>[FAILOVER — LINK PRINCIPAL VOLTOU]</b>\n"
                f"Dispositivo: <b>{dev['name']}</b> (<code>{dev['ip']}</code>)\n"
                f"Evento: O <b>Link 1 (PRINCIPAL)</b> voltou a responder normalmente.\n"
                f"Ação: Rota Principal reativada — tráfego restaurado para o <b>Link 1 (PRINCIPAL)</b>!\n"
                f"Horário: <code>{now_str}</code>"
            )
            log_preview = "O LINK PRINCIPAL VOLTOU -> Rota Principal reativada (Alerta Telegram enviado)"
        elif role_norm == "BACKUP" and state_norm == "DOWN":
            tg_msg = (
                f"⚠️ <b>[FAILOVER — LINK DE BACKUP CAIU]</b>\n"
                f"Dispositivo: <b>{dev['name']}</b> (<code>{dev['ip']}</code>)\n"
                f"Evento: O <b>Link 2 (BACKUP)</b> parou de responder ao ping externo.\n"
                f"Ação: Rota de Backup desativada preventivamente pelo Netwatch.\n"
                f"Horário: <code>{now_str}</code>"
            )
            log_preview = "O LINK DE BACKUP FOI INATIVADO -> Rota Backup desativada (Alerta Telegram enviado)"
        else:
            tg_msg = (
                f"✅ <b>[FAILOVER — LINK DE BACKUP ATIVO]</b>\n"
                f"Dispositivo: <b>{dev['name']}</b> (<code>{dev['ip']}</code>)\n"
                f"Evento: O <b>Link 2 (BACKUP)</b> voltou a responder normalmente.\n"
                f"Ação: Rota de Backup habilitada e pronta para contingência.\n"
                f"Horário: <code>{now_str}</code>"
            )
            log_preview = "LINK BACKUP ATIVO -> Rota Backup habilitada (Alerta Telegram enviado)"

        c.execute(
            """
            INSERT INTO command_logs (
                device_id, device_name, device_ip, action_key, command_executed,
                status, output_preview, duration_ms, client_ip, created_at
            ) VALUES (?, ?, ?, 'failover_switch', ?, ?, ?, 0, ?, ?)
            """,
            (
                dev["id"],
                dev["name"],
                dev["ip"],
                f"[Netwatch Failover] {role_norm} -> {state_norm}",
                "SUCCESS" if state_norm == "UP" else "ERROR",
                log_preview,
                client_ip or dev["ip"],
                now_str,
            ),
        )
        prune_command_logs(c, 200)
        conn.commit()
    finally:
        conn.close()

    await send_telegram(tg_msg, dev.get("telegram_destination_id"))
    return {"ok": True, "status": "dispatched", "link": role_norm, "state": state_norm}

