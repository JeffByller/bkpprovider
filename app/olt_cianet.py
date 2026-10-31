import asyncio
import re
import socket
import time

OLT_HOST = "172.18.0.30"
OLT_PORT = 23
OLT_USER = "root"
OLT_PASS = "Lh@Provedor2kk"


class CianetTelnet:
    def __init__(self, host: str = OLT_HOST, port: int = OLT_PORT, timeout: float = 8.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None

    def connect(self, user: str = OLT_USER, pwd: str = OLT_PASS):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)

        # Wait for username prompt
        self._read_until(b"User name:")
        self.sock.sendall(user.encode() + b"\n")

        # Wait for password prompt
        self._read_until(b"Password:")
        self.sock.sendall(pwd.encode() + b"\n")

        # Wait for user prompt (>)
        self._read_until(b"> ")
        self.sock.sendall(b"enable\n")

        # Wait for enable prompt (#)
        self._read_until(b"# ")
        self.sock.sendall(b"terminal length 0\n")
        self._read_until(b"# ")

    def _read_until(self, token: bytes, custom_timeout: float = None) -> str:
        buf = bytearray()
        timeout = custom_timeout or self.timeout
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                # Handle and suppress Telnet IAC sequences
                clean = bytearray()
                i = 0
                while i < len(chunk):
                    if chunk[i] == 0xFF and i + 2 < len(chunk):
                        cmd = chunk[i + 1]
                        opt = chunk[i + 2]
                        if cmd == 0xFD:  # DO -> reply WONT (0xFC)
                            self.sock.sendall(bytes([0xFF, 0xFC, opt]))
                        elif cmd == 0xFB:  # WILL -> reply DONT (0xFE)
                            self.sock.sendall(bytes([0xFF, 0xFE, opt]))
                        i += 3
                    else:
                        clean.append(chunk[i])
                        i += 1
                buf.extend(clean)
                if token in buf:
                    return buf.decode("ascii", errors="ignore")
            except socket.timeout:
                break
        return buf.decode("ascii", errors="ignore")

    def exec_cmd(self, cmd: str, timeout: float = 5.0) -> str:
        self.sock.sendall(cmd.encode() + b"\n")
        return self._read_until(b"# ", custom_timeout=timeout)

    def close(self):
        if self.sock:
            try:
                self.sock.sendall(b"exit\n")
                self.sock.close()
            except Exception:
                pass
            self.sock = None


def _get_optical_for_ont_sync(c: CianetTelnet, port: int, ont_id: int) -> dict:
    optical = {
        "rx_dbm": None,
        "tx_dbm": None,
        "olt_rx_dbm": None,
        "temp_c": None,
        "voltage_v": None,
    }
    try:
        # Must be in config-gpon-0/0 mode to run show ont optical-info
        c.exec_cmd("config", timeout=2.0)
        c.exec_cmd("interface gpon 0/0", timeout=2.0)
        out = c.exec_cmd(f"show ont optical-info {port} {ont_id}", timeout=4.0)
        c.exec_cmd("exit", timeout=2.0)
        c.exec_cmd("exit", timeout=2.0)

        m_rx = re.search(r"Rx optical power\(dBm\)\s*:\s*([-\d\.]+)", out)
        if m_rx:
            optical["rx_dbm"] = m_rx.group(1)

        m_tx = re.search(r"Tx optical power\(dBm\)\s*:\s*([-\d\.]+)", out)
        if m_tx:
            optical["tx_dbm"] = m_tx.group(1)

        m_oltrx = re.search(r"OLT Rx ONT optical power\(dBm\)\s*:\s*([-\d\.]+)", out)
        if m_oltrx:
            optical["olt_rx_dbm"] = m_oltrx.group(1)

        m_temp = re.search(r"Temperature\(C\)\s*:\s*([-\d\.]+)", out)
        if m_temp:
            optical["temp_c"] = m_temp.group(1)

        m_volt = re.search(r"Voltage\(V\)\s*:\s*([-\d\.]+)", out)
        if m_volt:
            optical["voltage_v"] = m_volt.group(1)
    except Exception:
        pass
    return optical


def search_ont_sync(query: str, fetch_optical: bool = True) -> list[dict]:
    clean_q = re.sub(r"[:\-\.\s]", "", query).upper()
    if not clean_q:
        return []

    c = CianetTelnet()
    c.connect()
    results = []
    try:
        raw = c.exec_cmd("show ont info all", timeout=8.0)
        # Parse table rows:
        # Format: 0/0 1  2      FHTTFE282DC4     Active   Online  success   mismatch  LOS
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("F/S") or line.startswith("-") or line.startswith("show"):
                continue
            parts = line.split()
            if len(parts) >= 6:
                fs = parts[0]
                port_str = parts[1]
                ont_id_str = parts[2]
                sn = parts[3]
                ctrl_flag = parts[4]
                run_state = parts[5]
                down_cause = parts[8] if len(parts) >= 9 else ""
                desc = " ".join(parts[9:]) if len(parts) >= 10 else ""

                if clean_q in sn.upper() or clean_q in desc.upper():
                    port = int(port_str) if port_str.isdigit() else 1
                    ont_id = int(ont_id_str) if ont_id_str.isdigit() else 1
                    item = {
                        "frame_slot": fs,
                        "port": port,
                        "ont_id": ont_id,
                        "sn": sn,
                        "status": run_state,
                        "control": ctrl_flag,
                        "down_cause": down_cause,
                        "description": desc,
                    }
                    if fetch_optical and run_state.lower() == "online":
                        opt = _get_optical_for_ont_sync(c, port, ont_id)
                        item.update(opt)
                    results.append(item)
    finally:
        c.close()
    return results


PON_SRV_PROFILES = {
    1: 2011,
    2: 2012,
    3: 2013,
    4: 2014,
    5: 1,     # fallback if 2015 is not configured
    6: 2016,
    7: 2017,
    8: 2018,
}


def get_unauthorized_onts_sync() -> list[dict]:
    c = CianetTelnet()
    c.connect()
    unauth = []
    try:
        raw = c.exec_cmd("show ont autofind all", timeout=6.0)
        # Parse autofind table if any ONTs exist
        for line in raw.splitlines():
            line = line.strip()
            if (
                not line
                or "no ont available" in line.lower()
                or line.startswith("Aging")
                or line.startswith("show ")
                or line.startswith("F/S")
                or line.startswith("-")
                or line.endswith("#")
                or "FD1608" in line
            ):
                continue

            parts = line.split()
            # Valid data line in FD1608S autofind starts with frame/slot, e.g. "0/0"
            if len(parts) >= 2 and re.match(r"^\d+/\d+$", parts[0]):
                port_str = parts[1]
                port_num = int(port_str) if port_str.isdigit() else 1
                sn_match = re.search(r"\b([A-Z0-9]{12,16})\b", line)
                sn_val = sn_match.group(1) if sn_match else (parts[2] if len(parts) > 2 else "DESCONHECIDO")
                unauth.append({
                    "port": port_num,
                    "sn": sn_val,
                    "raw": line,
                })
    finally:
        c.close()
    return unauth


def authorize_ont_sync(port: int, sn: str) -> tuple[bool, str]:
    c = CianetTelnet()
    c.connect()
    srv_profile = PON_SRV_PROFILES.get(port, 2010 + port if port in range(1, 9) else 1)
    line_profile = 1
    clean_sn = sn.strip().replace("-", "")
    try:
        c.exec_cmd("config", timeout=2.0)
        c.exec_cmd("interface gpon 0/0", timeout=2.0)
        out = c.exec_cmd(
            f"ont confirm {port} sn-auth {clean_sn} ont-lineprofile-id {line_profile} ont-srvprofile-id {srv_profile}",
            timeout=6.0,
        )
        c.exec_cmd("exit", timeout=2.0)
        c.exec_cmd("exit", timeout=2.0)
        if "error" in out.lower() or "failed" in out.lower() or "%" in out or "not exists" in out.lower():
            return False, f"Retorno OLT: {out.strip()}"
        return True, f"ONU {clean_sn} autorizada na PON {port} (LineProfile {line_profile}, SrvProfile {srv_profile}) com sucesso!"
    except Exception as e:
        return False, str(e)
    finally:
        c.close()


def deauthorize_ont_sync(port: int, ont_id: int) -> tuple[bool, str]:
    c = CianetTelnet()
    c.connect()
    try:
        c.exec_cmd("config", timeout=2.0)
        c.exec_cmd("interface gpon 0/0", timeout=2.0)
        out = c.exec_cmd(f"ont delete {port} {ont_id}", timeout=5.0)
        c.exec_cmd("exit", timeout=2.0)
        c.exec_cmd("exit", timeout=2.0)
        if "error" in out.lower() or "failed" in out.lower() or "%" in out:
            return False, f"Falha ao desautorizar: {out.strip()}"
        return True, f"ONU ID {ont_id} removida/desautorizada da PON {port} com sucesso!"
    except Exception as e:
        return False, str(e)
    finally:
        c.close()


async def search_ont_async(query: str) -> list[dict]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, search_ont_sync, query)


async def get_unauthorized_onts_async() -> list[dict]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, get_unauthorized_onts_sync)


async def authorize_ont_async(port: int, sn: str) -> tuple[bool, str]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, authorize_ont_sync, port, sn)


async def deauthorize_ont_async(port: int, ont_id: int) -> tuple[bool, str]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, deauthorize_ont_sync, port, ont_id)
