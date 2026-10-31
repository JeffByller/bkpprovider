import asyncio
import datetime
import json
import random
import re
import socket
import time

from app.crypto import decrypt_secret
from app.db import get_db, get_settings_typed, prune_command_logs
from app.mikrotik import (
    SSH_SEMAPHORE,
    _connect_ssh,
    _exec_ssh_cmd,
    _parse_resource_output,
)

# In-memory state for calculating delta bps (bits/sec) per device:
# device_id -> {"ts": float, "rx_bytes": int, "tx_bytes": int, "if_bytes": {if_name: (rx, tx)}}
_TRAFFIC_STATE: dict[int, dict] = {}

_SAFE_COMMUNITY_RE = re.compile(r"^[a-zA-Z0-9_@.!$-]{1,48}$")


# ---------- Lightweight Pure-Python ASN.1 BER SNMPv2c Client ----------

def _ber_encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    octets = []
    while length > 0:
        octets.insert(0, length & 0xFF)
        length >>= 8
    return bytes([0x80 | len(octets)] + octets)


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_encode_length(len(value)) + value


def _ber_encode_int(val: int) -> bytes:
    if val == 0:
        return _ber_tlv(0x02, b"\x00")
    octets = []
    n = val
    while n > 0:
        octets.insert(0, n & 0xFF)
        n >>= 8
    if octets[0] & 0x80:
        octets.insert(0, 0x00)
    return _ber_tlv(0x02, bytes(octets))


def _ber_encode_str(val: str) -> bytes:
    return _ber_tlv(0x04, val.encode("utf-8"))


def _ber_encode_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.strip(".").split(".") if x]
    if len(parts) < 2:
        raise ValueError(f"Invalid OID: {oid_str}")
    body = bytearray([parts[0] * 40 + parts[1]])
    for sub in parts[2:]:
        if sub == 0:
            body.append(0)
        else:
            stack = []
            while sub > 0:
                stack.insert(0, sub & 0x7F)
                sub >>= 7
            for i in range(len(stack) - 1):
                body.append(stack[i] | 0x80)
            body.append(stack[-1])
    return _ber_tlv(0x06, bytes(body))


def _build_snmp_v2c_get(community: str, oids: list[str], pdu_tag: int = 0xA0) -> tuple[int, bytes]:
    req_id = random.randint(10000, 9999999)
    varbinds = b"".join(_ber_tlv(0x30, _ber_encode_oid(oid) + _ber_tlv(0x05, b"")) for oid in oids)
    varbind_list = _ber_tlv(0x30, varbinds)
    pdu_body = _ber_encode_int(req_id) + _ber_encode_int(0) + _ber_encode_int(0) + varbind_list
    pdu = _ber_tlv(pdu_tag, pdu_body)
    msg = _ber_tlv(0x30, _ber_encode_int(1) + _ber_encode_str(community) + pdu)
    return req_id, msg


def _ber_decode_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_octets = first & 0x7F
    length = 0
    for _ in range(num_octets):
        length = (length << 8) | data[offset]
        offset += 1
    return length, offset


def _ber_decode_oid(val: bytes) -> str:
    if not val:
        return ""
    first = val[0]
    parts = [first // 40, first % 40]
    sub = 0
    for b in val[1:]:
        sub = (sub << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(sub)
            sub = 0
    return ".".join(str(p) for p in parts)


def _ber_decode_uint(val: bytes) -> int:
    n = 0
    for b in val:
        n = (n << 8) | b
    return n


def _parse_snmp_response(data: bytes) -> dict[str, any]:
    """Decodes an SNMPv2c GetResponse packet into {oid_str: decoded_value}."""
    results = {}
    if not data or data[0] != 0x30:
        return results
    _, idx = _ber_decode_length(data, 1)
    # Version
    if data[idx] != 0x02:
        return results
    vlen, idx = _ber_decode_length(data, idx + 1)
    idx += vlen
    # Community
    if data[idx] != 0x04:
        return results
    clen, idx = _ber_decode_length(data, idx + 1)
    idx += clen
    # PDU (0xA2 = GetResponse)
    if data[idx] != 0xA2:
        return results
    _, idx = _ber_decode_length(data, idx + 1)
    # req_id, error_status, error_index
    for _ in range(3):
        if data[idx] != 0x02:
            return results
        ilen, idx = _ber_decode_length(data, idx + 1)
        idx += ilen
    # VarBindList (0x30)
    if data[idx] != 0x30:
        return results
    vbl_len, idx = _ber_decode_length(data, idx + 1)
    end_vbl = idx + vbl_len
    while idx < end_vbl:
        if data[idx] != 0x30:
            break
        vb_len, idx = _ber_decode_length(data, idx + 1)
        vb_end = idx + vb_len
        if data[idx] != 0x06:
            idx = vb_end
            continue
        oid_len, idx = _ber_decode_length(data, idx + 1)
        oid_str = _ber_decode_oid(data[idx : idx + oid_len])
        idx += oid_len
        vtag = data[idx]
        val_len, idx = _ber_decode_length(data, idx + 1)
        raw_val = data[idx : idx + val_len]
        idx = vb_end

        if vtag in (0x02, 0x41, 0x42, 0x43, 0x46):  # Integer, Counter32, Gauge32, TimeTicks, Counter64
            results[oid_str] = _ber_decode_uint(raw_val)
        elif vtag == 0x04:  # OctetString
            results[oid_str] = raw_val.decode("utf-8", errors="replace")
        elif vtag == 0x06:  # OID
            results[oid_str] = _ber_decode_oid(raw_val)
        else:
            results[oid_str] = None
    return results


class _SNMPDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, packet: bytes, future: asyncio.Future):
        self.packet = packet
        self.future = future
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        transport.sendto(self.packet)

    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc):
        if not self.future.done():
            self.future.set_exception(exc)


async def snmp_query_udp(
    ip: str,
    port: int,
    community: str,
    oids: list[str],
    pdu_tag: int = 0xA0,
    timeout: float = 2.5,
) -> dict[str, any]:
    """Performs an asynchronous UDP SNMPv2c GET (0xA0) or GETNEXT (0xA1) query."""
    loop = asyncio.get_running_loop()
    _, packet = _build_snmp_v2c_get(community, oids, pdu_tag=pdu_tag)
    fut = loop.create_future()
    transport = None
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _SNMPDatagramProtocol(packet, fut),
            remote_addr=(ip, int(port or 161)),
            family=socket.AF_INET,
        )
        raw_resp = await asyncio.wait_for(fut, timeout=timeout)
        return _parse_snmp_response(raw_resp)
    except Exception:
        return {}
    finally:
        if transport:
            transport.close()


def _format_timeticks(ticks: int | None) -> str:
    if ticks is None:
        return ""
    total_secs = int(ticks) // 100
    days, rem = divmod(total_secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    if days > 0:
        return f"{days}d {hours:02d}:{mins:02d}:{secs:02d}"
    return f"{hours:02d}:{mins:02d}:{secs:02d}"


def _update_traffic_bps(device_id: int, total_rx_bytes: int, total_tx_bytes: int, if_list: list[dict]) -> tuple[int, int, list[dict]]:
    now_ts = time.monotonic()
    prev = _TRAFFIC_STATE.get(device_id)
    rx_bps = 0
    tx_bps = 0

    if prev and now_ts > prev["ts"]:
        dt = now_ts - prev["ts"]
        if dt >= 1.0:
            if total_rx_bytes >= prev["rx_bytes"]:
                rx_bps = int(((total_rx_bytes - prev["rx_bytes"]) * 8) / dt)
            if total_tx_bytes >= prev["tx_bytes"]:
                tx_bps = int(((total_tx_bytes - prev["tx_bytes"]) * 8) / dt)

            prev_ifs = prev.get("if_bytes", {})
            for item in if_list:
                if_name = item["name"]
                if if_name in prev_ifs:
                    p_rx, p_tx = prev_ifs[if_name]
                    item["rx_bps"] = int(((max(0, item["rx_bytes"] - p_rx)) * 8) / dt)
                    item["tx_bps"] = int(((max(0, item["tx_bytes"] - p_tx)) * 8) / dt)

    _TRAFFIC_STATE[device_id] = {
        "ts": now_ts,
        "rx_bytes": total_rx_bytes,
        "tx_bytes": total_tx_bytes,
        "if_bytes": {i["name"]: (i["rx_bytes"], i["tx_bytes"]) for i in if_list},
    }
    return rx_bps, tx_bps, if_list


async def poll_device_snmp_udp(dev: dict) -> tuple[bool, dict, str]:
    """
    Polls a device via native UDP SNMPv2c for Uptime, CPU, Memory, and Interface counters.
    """
    ip = dev["ip"]
    port = dev["snmp_port"] or 161
    community = dev["snmp_community"] or "public"

    # Core system OIDs (MikroTik RouterOS standard MIB-2 + HOST-RESOURCES-MIB)
    oid_sys_descr = "1.3.6.1.2.1.1.1.0"
    oid_sys_uptime = "1.3.6.1.2.1.1.3.0"
    oid_mem_total = "1.3.6.1.2.1.25.2.3.1.5.65536"
    oid_mem_used = "1.3.6.1.2.1.25.2.3.1.6.65536"
    oid_cpu_1 = "1.3.6.1.2.1.25.3.3.1.2.1"

    base_resp = await snmp_query_udp(
        ip,
        port,
        community,
        [oid_sys_descr, oid_sys_uptime, oid_mem_total, oid_mem_used, oid_cpu_1],
        pdu_tag=0xA0,
        timeout=2.5,
    )
    if not base_resp or oid_sys_uptime not in base_resp:
        return False, {}, "Sem resposta UDP na porta SNMP 161."

    uptime_str = _format_timeticks(base_resp.get(oid_sys_uptime))
    sys_descr = str(base_resp.get(oid_sys_descr) or "")

    # CPU load (if index .1 wasn't matched, do GETNEXT on hrProcessorLoad 1.3.6.1.2.1.25.3.3.1.2)
    cpu_load = base_resp.get(oid_cpu_1)
    if cpu_load is None:
        cpu_next = await snmp_query_udp(ip, port, community, ["1.3.6.1.2.1.25.3.3.1.2"], pdu_tag=0xA1, timeout=2.0)
        for k, v in cpu_next.items():
            if k.startswith("1.3.6.1.2.1.25.3.3.1.2.") and isinstance(v, int):
                cpu_load = v
                break

    mem_total_kb = base_resp.get(oid_mem_total)
    mem_used_kb = base_resp.get(oid_mem_used)
    mem_total_mb = round(mem_total_kb / 1024.0, 1) if isinstance(mem_total_kb, int) and mem_total_kb > 0 else None
    mem_used_mb = round(mem_used_kb / 1024.0, 1) if isinstance(mem_used_kb, int) and mem_used_kb >= 0 else None
    mem_pct = round((mem_used_kb / mem_total_kb) * 100.0, 1) if (mem_total_kb and mem_used_kb is not None) else None

    # Walk first 8 interfaces via GETNEXT chains on ifDescr, ifOperStatus, ifHCInOctets, ifHCOutOctets
    if_list = []
    cur_descr = "1.3.6.1.2.1.2.2.1.2"
    cur_oper = "1.3.6.1.2.1.2.2.1.8"
    cur_hc_in = "1.3.6.1.2.1.31.1.1.1.6"
    cur_hc_out = "1.3.6.1.2.1.31.1.1.1.10"

    total_rx = 0
    total_tx = 0
    for _ in range(8):
        nxt = await snmp_query_udp(
            ip, port, community, [cur_descr, cur_oper, cur_hc_in, cur_hc_out], pdu_tag=0xA1, timeout=1.8
        )
        if not nxt:
            break
        found_descr = next((k for k in nxt if k.startswith("1.3.6.1.2.1.2.2.1.2.")), None)
        if not found_descr:
            break
        if_idx = found_descr.split(".")[-1]
        if_name = str(nxt.get(found_descr) or f"if{if_idx}")
        oper_val = nxt.get(f"1.3.6.1.2.1.2.2.1.8.{if_idx}", 1)
        rx_val = int(nxt.get(f"1.3.6.1.2.1.31.1.1.1.6.{if_idx}") or 0)
        tx_val = int(nxt.get(f"1.3.6.1.2.1.31.1.1.1.10.{if_idx}") or 0)

        total_rx += rx_val
        total_tx += tx_val
        if_list.append({
            "name": if_name,
            "running": oper_val == 1,
            "rx_bytes": rx_val,
            "tx_bytes": tx_val,
            "rx_bps": 0,
            "tx_bps": 0,
        })
        cur_descr = found_descr
        cur_oper = f"1.3.6.1.2.1.2.2.1.8.{if_idx}"
        cur_hc_in = f"1.3.6.1.2.1.31.1.1.1.6.{if_idx}"
        cur_hc_out = f"1.3.6.1.2.1.31.1.1.1.10.{if_idx}"

    rx_bps, tx_bps, if_list = _update_traffic_bps(dev["id"], total_rx, total_tx, if_list)

    # Extract RouterOS version & board from sysDescr (e.g. "RouterOS RB750Gr3" or similar)
    ros_ver = dev.get("ros_version") or "auto"
    ros_detail = dev.get("ros_version_detail") or ""
    board = dev.get("board_name") or ""
    if sys_descr and not board and "RouterOS" in sys_descr:
        board = sys_descr.replace("RouterOS", "").strip()

    return True, {
        "source": "SNMPv2c (UDP)",
        "uptime_str": uptime_str,
        "cpu_load": cpu_load,
        "memory_total_mb": mem_total_mb,
        "memory_used_mb": mem_used_mb,
        "memory_used_pct": mem_pct,
        "rx_bps": rx_bps,
        "tx_bps": tx_bps,
        "interfaces": if_list[:12],
        "ros_version": ros_ver,
        "ros_version_detail": ros_detail,
        "board_name": board,
    }, "Coleta SNMP UDP realizada com sucesso."


def _parse_mikrotik_interfaces_stats(text: str) -> tuple[int, int, list[dict]]:
    """
    Parses RouterOS `/interface print stats-detail without-paging` output
    to extract interface running states and 64-bit rx-byte/tx-byte counters.
    """
    interfaces = []
    total_rx = 0
    total_tx = 0

    # Split into blocks per interface entry (starts with index number + flags, optionally followed by ;;; comment)
    blocks = re.split(r"\n(?=\s*\d+\s+[A-Z]*(?:\s+;;;[^\r\n]*[\r\n]+\s*|\s+)name=)", "\n" + text)
    for b in blocks:
        b = b.strip()
        if not b or "name=" not in b:
            continue
        m_flag = re.match(r"^\d+\s+([A-Z]*)\s+", b)
        flags = m_flag.group(1) if m_flag else ""
        running = "R" in flags and "X" not in flags

        m_name = re.search(r'name="([^"]+)"|name=(\S+)', b)
        name = (m_name.group(1) or m_name.group(2)) if m_name else "iface"

        m_rx = re.search(r"(?<![a-z-])rx-byte=([\d\s]+)", b)
        m_tx = re.search(r"(?<![a-z-])tx-byte=([\d\s]+)", b)
        rx_b = int(re.sub(r"\s+", "", m_rx.group(1))) if m_rx else 0
        tx_b = int(re.sub(r"\s+", "", m_tx.group(1))) if m_tx else 0

        # Skip virtual dynamic pppoe server sub-interfaces to keep main interfaces list concise
        if name.startswith("<pppoe-"):
            continue

        total_rx += rx_b
        total_tx += tx_b
        interfaces.append({
            "name": name,
            "running": running,
            "rx_bytes": rx_b,
            "tx_bytes": tx_b,
            "rx_bps": 0,
            "tx_bps": 0,
        })

    return total_rx, total_tx, interfaces[:15]


def _poll_metrics_ssh_sync(ip: str, port: int, username: str, password_plain: str) -> tuple[bool, dict, str]:
    ssh = None
    try:
        ssh = _connect_ssh(ip, port, username, password_plain, timeout=10)
        _, res_part, _ = _exec_ssh_cmd(
            ssh,
            "/system resource print without-paging",
            timeout=10,
        )
        _, if_part, _ = _exec_ssh_cmd(
            ssh,
            "/interface print stats-detail without-paging",
            timeout=12,
        )

        info = _parse_resource_output(res_part)
        total_rx, total_tx, if_list = _parse_mikrotik_interfaces_stats(if_part)
        info["total_rx"] = total_rx
        info["total_tx"] = total_tx
        info["interfaces"] = if_list
        return True, info, "Métricas coletadas via SSH (Fallback SNMP)"
    except Exception as e:
        return False, {}, f"Falha na coleta: {e}"
    finally:
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass


async def collect_device_metrics(dev: dict) -> tuple[bool, dict, str]:
    """
    Attempts native UDP SNMPv2c polling first. If UDP 161 is filtered by ISP/firewall
    and the device has SSH credentials, seamlessly collects the same metrics via SSH.
    """
    ok, data, msg = await poll_device_snmp_udp(dev)
    if ok:
        return True, data, msg

    password_plain = decrypt_secret(dev.get("ssh_password"))
    if dev.get("ssh_username") and password_plain:
        async with SSH_SEMAPHORE:
            loop = asyncio.get_running_loop()
            ssh_ok, info, ssh_msg = await loop.run_in_executor(
                None,
                _poll_metrics_ssh_sync,
                dev["ip"],
                dev["ssh_port"],
                dev["ssh_username"],
                password_plain,
            )
        if ssh_ok:
            rx_bps, tx_bps, if_list = _update_traffic_bps(
                dev["id"],
                info.get("total_rx", 0),
                info.get("total_tx", 0),
                info.get("interfaces", []),
            )
            return True, {
                "source": "SSH (UDP 161 filtrado na WAN)",
                "uptime_str": info.get("uptime_str") or "",
                "cpu_load": info.get("cpu_load"),
                "memory_total_mb": info.get("memory_total_mb"),
                "memory_used_mb": info.get("memory_used_mb"),
                "memory_used_pct": info.get("memory_used_pct"),
                "rx_bps": rx_bps,
                "tx_bps": tx_bps,
                "interfaces": if_list,
                "ros_version": info.get("ros_version"),
                "ros_version_detail": info.get("ros_version_detail"),
                "board_name": info.get("board_name"),
            }, ssh_msg

    return False, {}, msg


def _normalize_allowed_ip(raw_ip: str) -> tuple[str, str]:
    """Returns (clean_ip_or_cidr_for_firewall, cidr_for_snmp_community)."""
    ip_str = (raw_ip or "38.225.221.159").strip()
    if "/" in ip_str:
        base_ip, mask = ip_str.split("/", 1)
        clean_fw = base_ip.strip() if mask.strip() == "32" else ip_str
        return clean_fw, ip_str
    return ip_str, f"{ip_str}/32"


def _provision_snmp_ssh_sync(
    ip: str,
    port: int,
    username: str,
    password_plain: str,
    community: str,
    allowed_ip: str = "38.225.221.159",
    allow_firewall: bool = True,
) -> tuple[bool, dict, str]:
    """
    Connects via SSH to a MikroTik v6 or v7 router and configures SNMP securely:
    1. Restricts the SNMP community `addresses` to `allowed_ip/32` (default 38.225.221.159/32) with read-access=yes, write-access=no.
    2. Enables the SNMP service (/snmp set enabled=yes).
    3. Configures /ip firewall filter on chain=input UDP 161 to ACCEPT only `allowed_ip` and DROP all other IPs (`src-address=!allowed_ip`).
    """
    fw_ip, comm_cidr = _normalize_allowed_ip(allowed_ip)
    ssh = None
    try:
        ssh = _connect_ssh(ip, port, username, password_plain, timeout=12)
        _, res_out, _ = _exec_ssh_cmd(ssh, "/system resource print without-paging", timeout=10)
        info = _parse_resource_output(res_out)

        # 1. Configure SNMP community restricted to comm_cidr (e.g. 38.225.221.159/32)
        _, comm_out, _ = _exec_ssh_cmd(
            ssh, f'/snmp community print detail without-paging where name="{community}"', timeout=10
        )
        if f'name="{community}"' in comm_out or f"name={community}" in comm_out:
            _exec_ssh_cmd(
                ssh,
                f'/snmp community set [ find name="{community}" ] read-access=yes write-access=no addresses={comm_cidr} disabled=no',
                timeout=10,
            )
            comm_action = f"Community '{community}' restrita exclusivamente a {comm_cidr}."
        else:
            _exec_ssh_cmd(
                ssh,
                f'/snmp community add name="{community}" addresses={comm_cidr} read-access=yes write-access=no disabled=no',
                timeout=10,
            )
            comm_action = f"Community '{community}' criada e restrita a {comm_cidr}."

        # 2. Enable SNMP service and point trap-community to the active community so 'public' can be disabled
        _exec_ssh_cmd(ssh, f'/snmp set enabled=yes trap-community="{community}"', timeout=10)
        _exec_ssh_cmd(ssh, "/snmp set enabled=yes", timeout=10)

        # 3. Disable and lock down the default 'public' community (if a custom community is used)
        if community.lower() != "public":
            _exec_ssh_cmd(
                ssh,
                '/snmp community set [ find name="public" ] read-access=no write-access=no addresses=127.0.0.1/32',
                timeout=10,
            )
            _exec_ssh_cmd(
                ssh,
                '/snmp community set [ find name="public" ] disabled=yes',
                timeout=10,
            )
            comm_action += " Community padrão 'public' desativada (disabled=yes, read-access=no)."

        # 3. Firewall Input rules: Accept ONLY fw_ip on UDP 161, DROP everyone else on UDP 161
        fw_action = ""
        if allow_firewall:
            # Remove any old BKPProvider SNMP rules first to avoid duplicates
            for old_comment in ("BKPProvider SNMP", "BKPProvider SNMP Allow", "BKPProvider SNMP Drop"):
                _exec_ssh_cmd(
                    ssh,
                    f'/ip firewall filter remove [ find comment="{old_comment}" ]',
                    timeout=10,
                )

            # Insert DROP rule for any IP != fw_ip at top (place-before=0), then ACCEPT rule for fw_ip before it (place-before=0)
            drop_cmd_top = (
                f'/ip firewall filter add chain=input protocol=udp dst-port=161 src-address=!{fw_ip} '
                f'action=drop comment="BKPProvider SNMP Drop" place-before=0'
            )
            _, out_d, err_d = _exec_ssh_cmd(ssh, drop_cmd_top, timeout=10)
            if err_d or "invalid" in out_d.lower() or "no such item" in out_d.lower():
                _exec_ssh_cmd(
                    ssh,
                    f'/ip firewall filter add chain=input protocol=udp dst-port=161 src-address=!{fw_ip} '
                    f'action=drop comment="BKPProvider SNMP Drop"',
                    timeout=10,
                )

            allow_cmd_top = (
                f'/ip firewall filter add chain=input protocol=udp dst-port=161 src-address={fw_ip} '
                f'action=accept comment="BKPProvider SNMP Allow" place-before=0'
            )
            _, out_a, err_a = _exec_ssh_cmd(ssh, allow_cmd_top, timeout=10)
            if err_a or "invalid" in out_a.lower() or "no such item" in out_a.lower():
                _exec_ssh_cmd(
                    ssh,
                    f'/ip firewall filter add chain=input protocol=udp dst-port=161 src-address={fw_ip} '
                    f'action=accept comment="BKPProvider SNMP Allow"',
                    timeout=10,
                )

            fw_action = f" Firewall UDP/161: ACCEPT exclusivo para {fw_ip} e DROP para qualquer outro IP."

        return (
            True,
            info,
            f"SNMP habilitado ({info.get('ros_version_detail') or 'OK'}). {comm_action}{fw_action}",
        )
    except Exception as e:
        return False, {}, f"Falha ao configurar SNMP via SSH: {e}"
    finally:
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass


async def provision_device_snmp(
    dev: dict,
    community: str = "public",
    snmp_port: int = 161,
    allowed_ip: str = "38.225.221.159",
    allow_firewall: bool = True,
    client_ip: str = "",
) -> dict:
    """
    Configures SNMP automatically on the remote MikroTik via SSH, restricts access
    exclusively to `allowed_ip` (both in /snmp community and /ip firewall filter),
    validates metric collection, updates the device record in DB, and logs in command_logs.
    """
    community = (community or "public").strip()
    if not _SAFE_COMMUNITY_RE.match(community):
        return {"ok": False, "message": "Nome de community SNMP inválido (use apenas letras, números, _, -, .)."}

    allowed_ip = (allowed_ip or "38.225.221.159").strip()
    if not re.match(r"^[0-9a-fA-F.:/]{3,43}$", allowed_ip):
        return {"ok": False, "message": "IP autorizado para SNMP inválido."}

    password_plain = decrypt_secret(dev.get("ssh_password"))
    if not dev.get("ssh_username") or not password_plain:
        return {"ok": False, "message": "Cadastre o usuário e senha SSH do dispositivo antes de provisionar o SNMP automaticamente."}

    t0 = time.monotonic()
    async with SSH_SEMAPHORE:
        loop = asyncio.get_running_loop()
        ssh_ok, info, prov_msg = await loop.run_in_executor(
            None,
            _provision_snmp_ssh_sync,
            dev["ip"],
            dev["ssh_port"],
            dev["ssh_username"],
            password_plain,
            community,
            allowed_ip,
            allow_firewall,
        )
    duration_ms = int((time.monotonic() - t0) * 1000)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not ssh_ok:
        conn = get_db()
        try:
            c = conn.cursor()
            c.execute(
                "UPDATE devices SET snmp_status='ERROR', snmp_last_error=?, snmp_last_check=? WHERE id=?",
                (prov_msg, now, dev["id"]),
            )
            c.execute(
                """
                INSERT INTO command_logs (device_id, device_name, device_ip, action_key, command_executed, status, output_preview, duration_ms, client_ip, created_at)
                VALUES (?, ?, ?, 'snmp_provision', '/snmp set enabled=yes', 'ERROR', ?, ?, ?, ?)
                """,
                (dev["id"], dev["name"], dev["ip"], prov_msg, duration_ms, client_ip, now),
            )
            prune_command_logs(c, 200)
            conn.commit()
        finally:
            conn.close()
        return {"ok": False, "message": prov_msg}

    # Test metric collection right away
    dev_updated = dict(dev)
    dev_updated["snmp_community"] = community
    dev_updated["snmp_port"] = int(snmp_port or 161)
    poll_ok, metrics, poll_msg = await collect_device_metrics(dev_updated)

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            """
            UPDATE devices
            SET snmp_enabled = 1,
                snmp_community = ?,
                snmp_port = ?,
                snmp_status = ?,
                snmp_last_error = ?,
                snmp_last_check = ?,
                ros_version = COALESCE(NULLIF(?, 'auto'), ros_version),
                ros_version_detail = COALESCE(NULLIF(?, ''), ros_version_detail),
                board_name = COALESCE(NULLIF(?, ''), board_name),
                uptime_str = COALESCE(NULLIF(?, ''), uptime_str),
                cpu_load = COALESCE(?, cpu_load),
                memory_total_mb = COALESCE(?, memory_total_mb),
                memory_used_mb = COALESCE(?, memory_used_mb),
                memory_used_pct = COALESCE(?, memory_used_pct),
                rx_bps = COALESCE(?, rx_bps),
                tx_bps = COALESCE(?, tx_bps),
                interfaces_json = ?
            WHERE id = ?
            """,
            (
                community,
                int(snmp_port or 161),
                "OK" if poll_ok else "ERROR",
                "" if poll_ok else poll_msg,
                now,
                metrics.get("ros_version") or info.get("ros_version"),
                metrics.get("ros_version_detail") or info.get("ros_version_detail"),
                metrics.get("board_name") or info.get("board_name"),
                metrics.get("uptime_str") or info.get("uptime_str"),
                metrics.get("cpu_load") if metrics.get("cpu_load") is not None else info.get("cpu_load"),
                metrics.get("memory_total_mb") or info.get("memory_total_mb"),
                metrics.get("memory_used_mb") or info.get("memory_used_mb"),
                metrics.get("memory_used_pct") or info.get("memory_used_pct"),
                metrics.get("rx_bps", 0),
                metrics.get("tx_bps", 0),
                json.dumps(metrics.get("interfaces", []), ensure_ascii=False),
                dev["id"],
            ),
        )
        if poll_ok:
            c.execute(
                """
                INSERT INTO device_metrics (device_id, timestamp, latency_ms, cpu_load, memory_used_pct, rx_bps, tx_bps)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dev["id"],
                    now,
                    dev.get("latency_ms"),
                    metrics.get("cpu_load") if metrics.get("cpu_load") is not None else info.get("cpu_load"),
                    metrics.get("memory_used_pct") or info.get("memory_used_pct"),
                    metrics.get("rx_bps", 0),
                    metrics.get("tx_bps", 0),
                ),
            )
        full_summary = f"{prov_msg} | Coleta: {metrics.get('source', poll_msg)}"
        c.execute(
            """
            INSERT INTO command_logs (device_id, device_name, device_ip, action_key, command_executed, status, output_preview, duration_ms, client_ip, created_at)
            VALUES (?, ?, ?, 'snmp_provision', ?, 'SUCCESS', ?, ?, ?, ?)
            """,
            (
                dev["id"],
                dev["name"],
                dev["ip"],
                f'/snmp set enabled=yes; /snmp community ({community})',
                full_summary,
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
        "ok": True,
        "message": f"{prov_msg}\nMétodo de coleta ativo: {metrics.get('source', 'SNMP')}",
        "metrics": metrics,
    }


async def run_snmp_cycle(force_all: bool = False):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    try:
        c = conn.cursor()
        # Automatically disable auto-poll for devices whose temporary analysis window expired
        c.execute(
            """
            UPDATE devices
            SET snmp_auto_poll = 0, snmp_auto_until = NULL
            WHERE snmp_auto_poll = 1
              AND snmp_auto_until IS NOT NULL
              AND snmp_auto_until != ''
              AND snmp_auto_until <= ?
            """,
            (now,),
        )
        if c.rowcount and c.rowcount > 0:
            conn.commit()

        if force_all:
            c.execute("SELECT * FROM devices WHERE active=1 AND snmp_enabled=1")
        else:
            c.execute("SELECT * FROM devices WHERE active=1 AND snmp_enabled=1 AND snmp_auto_poll=1")
        devices = [dict(r) for r in c.fetchall()]
    finally:
        conn.close()

    if not devices:
        return

    async def _poll_one(d):
        ok, data, msg = await collect_device_metrics(d)
        return d, ok, data, msg

    results = await asyncio.gather(*(_poll_one(d) for d in devices), return_exceptions=True)

    updates = []
    metric_rows = []
    for item in results:
        if not isinstance(item, tuple):
            continue
        d, ok, data, msg = item
        if ok:
            updates.append((
                "OK",
                "",
                now,
                data.get("uptime_str") or d.get("uptime_str") or "",
                data.get("cpu_load"),
                data.get("memory_total_mb"),
                data.get("memory_used_mb"),
                data.get("memory_used_pct"),
                data.get("rx_bps", 0),
                data.get("tx_bps", 0),
                json.dumps(data.get("interfaces", []), ensure_ascii=False),
                d["id"],
            ))
            metric_rows.append((
                d["id"],
                now,
                d.get("latency_ms"),
                data.get("cpu_load"),
                data.get("memory_used_pct"),
                data.get("rx_bps", 0),
                data.get("tx_bps", 0),
            ))
        else:
            updates.append((
                "ERROR",
                msg,
                now,
                d.get("uptime_str") or "",
                d.get("cpu_load"),
                d.get("memory_total_mb"),
                d.get("memory_used_mb"),
                d.get("memory_used_pct"),
                0,
                0,
                d.get("interfaces_json") or "[]",
                d["id"],
            ))

    if not updates:
        return

    settings = get_settings_typed()
    retention_days = max(settings.get("metrics_retention_days", 7), 1)
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=retention_days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    try:
        c = conn.cursor()
        c.executemany(
            """
            UPDATE devices
            SET snmp_status=?, snmp_last_error=?, snmp_last_check=?,
                uptime_str=?, cpu_load=?, memory_total_mb=?, memory_used_mb=?,
                memory_used_pct=?, rx_bps=?, tx_bps=?, interfaces_json=?
            WHERE id=?
            """,
            updates,
        )
        if metric_rows:
            c.executemany(
                """
                INSERT INTO device_metrics (device_id, timestamp, latency_ms, cpu_load, memory_used_pct, rx_bps, tx_bps)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                metric_rows,
            )
        c.execute("DELETE FROM device_metrics WHERE timestamp < ?", (cutoff,))
        conn.commit()
    finally:
        conn.close()


async def snmp_worker():
    while True:
        settings = get_settings_typed()
        interval = max(settings.get("snmp_interval_seconds", 60), 15)
        try:
            await run_snmp_cycle()
        except Exception as e:
            print(f"[SNMP Worker Error] {e}")
        await asyncio.sleep(interval)
