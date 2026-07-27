import asyncio
import os
import sqlite3
import datetime
import secrets
import glob
import aiohttp
import paramiko
from contextlib import asynccontextmanager
from fastapi import FastAPI, Form, Request, HTTPException, Query, Response, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
import uvicorn

DB_FILE = "/app/data/monitor.db"

# Session storage for web authentication (in-memory)
ACTIVE_SESSIONS = set()

ADMIN_PASSWORD = "DtMzN51NkYuDe4"

def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ping_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip TEXT NOT NULL,
            consecutive_failures INTEGER DEFAULT 0,
            status TEXT DEFAULT 'UP',
            last_check TIMESTAMP,
            alert_sent INTEGER DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mikrotik_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER DEFAULT 22,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            last_backup TIMESTAMP,
            last_status TEXT DEFAULT 'PENDING'
        )
    """)
    conn.commit()
    conn.close()


def get_setting(key, default=""):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = c.fetchone()
    conn.close()
    return row["value"] if row else default

def set_setting(key, value):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=?", (key, value, value))
    conn.commit()
    conn.close()

async def send_telegram(message):
    token = get_setting("telegram_bot_token")
    chat_id = get_setting("telegram_chat_id")
    if not token or not chat_id:
        print("[Telegram] Bot Token or Chat ID not configured.")
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=payload) as resp:
                if resp.status != 200:
                    print(f"[Telegram Error] {await resp.text()}")
    except Exception as e:
        print(f"[Telegram Exception] {e}")

async def ping_ip(ip):
    # Sends 1 ICMP packet with timeout 2 sec
    proc = await asyncio.create_subprocess_exec(
        "ping", "-c", "1", "-W", "2", ip,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL
    )
    res = await proc.wait()
    return res == 0

async def icmp_worker():
    while True:
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT * FROM ping_targets")
            targets = c.fetchall()
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            for t in targets:
                target_id = t["id"]
                name = t["name"]
                ip = t["ip"]
                failures = t["consecutive_failures"]
                status = t["status"]
                alert_sent = t["alert_sent"]

                is_up = await ping_ip(ip)

                if is_up:
                    if status == "DOWN":
                        await send_telegram(f"🟢 <b>[RECOVERED]</b> Host <b>{name}</b> ({ip}) está online novamente!")
                    c.execute(
                        "UPDATE ping_targets SET consecutive_failures=0, status='UP', last_check=?, alert_sent=0 WHERE id=?",
                        (now, target_id)
                    )
                else:
                    new_failures = failures + 1
                    new_status = status
                    new_alert_sent = alert_sent

                    # Check interval is 15s. 4 consecutive failures = 60s (~1 min)
                    if new_failures >= 4:
                        new_status = "DOWN"
                        if alert_sent == 0:
                            await send_telegram(f"🚨 <b>[ALERT - DOWN]</b> Host <b>{name}</b> ({ip}) sem resposta ICMP há 1 minuto!")
                            new_alert_sent = 1

                    c.execute(
                        "UPDATE ping_targets SET consecutive_failures=?, status=?, last_check=?, alert_sent=? WHERE id=?",
                        (new_failures, new_status, now, new_alert_sent, target_id)
                    )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[ICMP Worker Error] {e}")

        await asyncio.sleep(15)

def cleanup_old_backups(clean_name, ip, keep=7):
    try:
        prefix = f"/app/backups/{clean_name}_{ip}_*.txt"
        files = glob.glob(prefix)
        files.sort()
        if len(files) > keep:
            files_to_delete = files[:-keep]
            for f in files_to_delete:
                try:
                    if os.path.exists(f):
                        os.remove(f)
                except Exception as e:
                    print(f"[Backup Cleanup Error] {f}: {e}")
    except Exception as e:
        print(f"[Cleanup Error] {e}")

def backup_mikrotik_ssh(clean_name, ip, port, username, password, filename):
    os.makedirs("/app/backups", exist_ok=True)
    cleanup_old_backups(clean_name, ip, keep=6)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, port=port, username=username, password=password, timeout=10)
        
        remote_file_name = f"backup_{filename}"
        ssh.exec_command(f"/export file={remote_file_name}")
        import time
        time.sleep(3)

        sftp = ssh.open_sftp()
        local_path = f"/app/backups/{filename}.txt"

        try:
            sftp.get(f"{remote_file_name}.rsc", local_path)
            remote_to_remove = f"{remote_file_name}.rsc"
        except:
            sftp.get(remote_file_name, local_path)
            remote_to_remove = remote_file_name
        
        try:
            ssh.exec_command(f"/file remove {remote_to_remove}")
        except:
            pass

        sftp.close()
        ssh.close()

        cleanup_old_backups(clean_name, ip, keep=7)
        return True, "Backup realizado com sucesso!"
    except Exception as e:
        return False, str(e)

async def run_all_backups():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM mikrotik_devices")
        devices = c.fetchall()
        conn.close()

        for dev in devices:
            dev_id = dev["id"]
            name = dev["name"]
            ip = dev["ip"]
            port = dev["port"]
            username = dev["username"]
            password = dev["password"]

            date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            clean_name = "".join(x for x in name if x.isalnum() or x in ('_', '-'))
            filename = f"{clean_name}_{ip}_{date_str}"

            loop = asyncio.get_event_loop()
            success, msg = await loop.run_in_executor(
                None, backup_mikrotik_ssh, clean_name, ip, port, username, password, filename
            )

            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn_up = get_db()
            c_up = conn_up.cursor()
            if success:
                c_up.execute("UPDATE mikrotik_devices SET last_backup=?, last_status=? WHERE id=?", (now, "SUCCESS", dev_id))
                await send_telegram(f"✅ <b>[Backup Automático]</b>\nDispositivo: <b>{name}</b> ({ip})\nBackup realizado com sucesso!")
            else:
                c_up.execute("UPDATE mikrotik_devices SET last_status=? WHERE id=?", (f"FAILED: {msg}", dev_id))
                await send_telegram(f"❌ <b>[Falha no Backup Automático]</b>\nDispositivo: <b>{name}</b> ({ip})\nErro: <code>{msg}</code>")
            conn_up.commit()
            conn_up.close()
    except Exception as e:
        print(f"[Mikrotik Backup Error] {e}")



async def mikrotik_worker():
    while True:
        now = datetime.datetime.now()
        target = now.replace(hour=17, minute=0, second=0, microsecond=0)
        if now >= target:
            target += datetime.timedelta(days=1)
        
        sleep_seconds = (target - now).total_seconds()
        print(f"[Mikrotik Worker] Próximo backup automático agendado para: {target.strftime('%Y-%m-%d %H:%M:%S')} (em {int(sleep_seconds)} segundos)")
        await asyncio.sleep(sleep_seconds)
        await run_all_backups()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    asyncio.create_task(icmp_worker())
    asyncio.create_task(mikrotik_worker())
    yield

app = FastAPI(title="MeuProvedor Monitor & Backup", lifespan=lifespan)

def is_authenticated(session_token: str) -> bool:
    return session_token in ACTIVE_SESSIONS if session_token else False

@app.get("/login", response_class=HTMLResponse)
async def login_page(error: str = None):
    err_html = f'<div style="color: red; margin-bottom: 10px; font-weight: bold;">{error}</div>' if error else ''
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - MeuProvedor</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #1a1a2e; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
            .login-box {{ background: #16213e; padding: 40px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); width: 320px; }}
            h2 {{ text-align: center; color: #0f3460; margin-bottom: 25px; color: #00fff5; }}
            input[type=password] {{ width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #0f3460; border-radius: 5px; background: #0f3460; color: #fff; box-sizing: border-box; }}
            button {{ width: 100%; padding: 12px; background-color: #e94560; color: white; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; margin-top: 10px; }}
            button:hover {{ background-color: #ff2e63; }}
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>🔒 MeuProvedor Login</h2>
            {err_html}
            <form action="/login" method="post">
                <label>Senha de Acesso:</label>
                <input type="password" name="password" placeholder="Digite a senha" required autofocus>
                <button type="submit">Entrar</button>
            </form>
        </div>
    </body>
    </html>
    """

@app.post("/login")
async def login_submit(password: str = Form(...)):
    if password == ADMIN_PASSWORD:
        token = secrets.token_hex(32)
        ACTIVE_SESSIONS.add(token)
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(key="session_token", value=token, httponly=True, samesite="lax")
        return response
    else:
        return RedirectResponse(url="/login?error=Senha+Incorreta!", status_code=303)

@app.get("/logout")
async def logout(session_token: str = Cookie(None)):
    if session_token in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS.remove(session_token)
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(key="session_token")
    return response

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, session_token: str = Cookie(None)):
    if not is_authenticated(session_token):
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM ping_targets")
    targets = c.fetchall()

    c.execute("SELECT * FROM mikrotik_devices")
    devices = c.fetchall()
    conn.close()

    bot_token = get_setting("telegram_bot_token")
    chat_id = get_setting("telegram_chat_id")

    targets_rows = ""
    for t in targets:
        badge = "<span style='color: green; font-weight: bold;'>UP</span>" if t["status"] == "UP" else "<span style='color: red; font-weight: bold;'>DOWN</span>"
        targets_rows += f"""
        <tr>
            <td>{t['id']}</td>
            <td>{t['name']}</td>
            <td>{t['ip']}</td>
            <td>{badge}</td>
            <td>{t['consecutive_failures']}</td>
            <td>{t['last_check'] or '-'}</td>
            <td><a href="/target/delete/{t['id']}" onclick="return confirm('Tem certeza que deseja remover este IP?');" style="color: red; font-weight: bold;">Remover</a></td>
        </tr>
        """

    devices_rows = ""
    for d in devices:
        status_color = "green" if d["last_status"] == "SUCCESS" else "orange" if d["last_status"] == "PENDING" else "red"
        clean_name = "".join(x for x in d["name"] if x.isalnum() or x in ('_', '-'))
        prefix = f"{clean_name}_{d['ip']}_"
        
        file_options = ""
        if os.path.exists("/app/backups"):
            all_files = sorted(glob.glob(f"/app/backups/{prefix}*.txt"), reverse=True)[:7]
            for f in all_files:
                fname = os.path.basename(f)
                file_options += f'<option value="{fname}">{fname}</option>'

        download_html = ""
        if file_options:
            download_html = f"""
            <select id="file_{d['id']}" style="padding: 4px; margin-right: 5px;">
                {file_options}
            </select>
            <button type="button" onclick="downloadBackup({d['id']})" style="padding: 4px 8px; background-color: #17a2b8;">Baixar</button>
            """
        else:
            download_html = "<span style='color: #888;'>Nenhum backup</span>"

        devices_rows += f"""
        <tr>
            <td>{d['id']}</td>
            <td>{d['name']}</td>
            <td>{d['ip']}:{d['port']}</td>
            <td>{d['username']}</td>
            <td>{d['last_backup'] or '-'}</td>
            <td><span style="color: {status_color}; font-weight: bold;">{d['last_status']}</span></td>
            <td>
                {download_html}
            </td>
            <td>
                <button type="button" onclick="triggerBackup({d['id']}, '{clean_name}')" style="background-color: #007bff; padding: 4px 8px; border: none; border-radius: 4px; color: white; cursor: pointer; margin-right: 8px;">Backup Agora</button>
                <a href="/mikrotik/delete/{d['id']}" onclick="return confirm('Tem certeza que deseja remover este dispositivo?');" style="color: red; font-weight: bold;">Remover</a>
            </td>
        </tr>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MeuProvedor - Monitor & Backup</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f4f6f9; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; background: white; padding: 15px 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
            h1, h2 {{ color: #333; margin: 0; }}
            .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            th {{ background-color: #007bff; color: white; }}
            input[type=text], input[type=password], input[type=number] {{ padding: 8px; margin: 5px 0; border: 1px solid #ccc; border-radius: 4px; width: 100%; box-sizing: border-box; }}
            button {{ background-color: #28a745; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; }}
            button:hover {{ background-color: #218838; }}
            .btn-logout {{ background-color: #dc3545; color: white; text-decoration: none; padding: 8px 15px; border-radius: 4px; font-weight: bold; }}
            .btn-logout:hover {{ background-color: #c82333; }}
            .form-group {{ margin-bottom: 10px; }}
            .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        </style>
        <script>
            function downloadBackup(devId) {{
                var select = document.getElementById("file_" + devId);
                var filename = select.value;
                var password = prompt("Digite a senha para autorizar o download do backup:");
                if (password !== null && password !== "") {{
                    window.location.href = "/mikrotik/download?filename=" + encodeURIComponent(filename) + "&password=" + encodeURIComponent(password);
                }}
            }}
            function triggerBackup(devId, devName) {{
                window.location.href = "/mikrotik/backup-now/" + devId;
            }}
        </script>
    </head>

    <body>
        <div class="header">
            <h1>📡 MeuProvedor - Painel de Controle</h1>
            <a href="/logout" class="btn-logout">Sair (Logout)</a>
        </div>
        
        <div class="card">
            <h2>⚙️ Configuração Telegram</h2>
            <form action="/settings/config" method="post">
                <div class="grid">
                    <div class="form-group">
                        <label>Bot Token Telegram:</label>
                        <input type="text" name="telegram_bot_token" value="{bot_token}" placeholder="Ex: 123456789:ABCdef...">
                    </div>
                    <div class="form-group">
                        <label>Chat ID do Grupo:</label>
                        <input type="text" name="telegram_chat_id" value="{chat_id}" placeholder="Ex: -100123456789">
                    </div>
                </div>
                <button type="submit">Salvar Configurações</button>
            </form>
        </div>

        <div class="card">
            <h2>🎯 Monitoramento ICMP (Ping)</h2>
            <form action="/target/add" method="post" style="margin-bottom: 15px;">
                <div class="grid">
                    <div class="form-group">
                        <input type="text" name="name" placeholder="Nome do Dispositivo/Local" required>
                    </div>
                    <div class="form-group">
                        <input type="text" name="ip" placeholder="IP para Ping" required>
                    </div>
                </div>
                <button type="submit">Cadastrar IP para Ping</button>
            </form>

            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Nome</th>
                        <th>IP</th>
                        <th>Status</th>
                        <th>Falhas Consecutivas</th>
                        <th>Última Checagem</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
                    {targets_rows}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>💾 Backup Mikrotik (v6 / v7)</h2>
            <form action="/mikrotik/add" method="post" style="margin-bottom: 15px;">
                <div class="grid">
                    <div class="form-group">
                        <input type="text" name="name" placeholder="Nome da RB" required>
                        <input type="text" name="ip" placeholder="IP da RB" required>
                    </div>
                    <div class="form-group">
                        <input type="number" name="port" value="22" placeholder="Porta SSH" required>
                        <input type="text" name="username" placeholder="Usuário" required>
                        <input type="password" name="password" placeholder="Senha" required>
                    </div>
                </div>
                <button type="submit">Cadastrar Mikrotik</button>
            </form>

            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Nome</th>
                        <th>IP:Porta</th>
                        <th>Usuário</th>
                        <th>Último Backup</th>
                        <th>Status Backup</th>
                        <th>Arquivos de Backup</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
                    {devices_rows}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.post("/settings/config")
async def save_config(telegram_bot_token: str = Form(...), telegram_chat_id: str = Form(...), session_token: str = Cookie(None)):
    if not is_authenticated(session_token):
        raise HTTPException(status_code=401, detail="Não autorizado")
    set_setting("telegram_bot_token", telegram_bot_token.strip())
    set_setting("telegram_chat_id", telegram_chat_id.strip())
    return RedirectResponse(url="/", status_code=303)

@app.post("/target/add")
async def add_target(name: str = Form(...), ip: str = Form(...), session_token: str = Cookie(None)):
    if not is_authenticated(session_token):
        raise HTTPException(status_code=401, detail="Não autorizado")
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO ping_targets (name, ip) VALUES (?, ?)", (name.strip(), ip.strip()))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/", status_code=303)

@app.get("/target/delete/{target_id}")
async def delete_target(target_id: int, session_token: str = Cookie(None)):
    if not is_authenticated(session_token):
        raise HTTPException(status_code=401, detail="Não autorizado")
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM ping_targets WHERE id=?", (target_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/", status_code=303)

@app.post("/mikrotik/add")
async def add_mikrotik(name: str = Form(...), ip: str = Form(...), port: int = Form(22), username: str = Form(...), password: str = Form(...), session_token: str = Cookie(None)):
    if not is_authenticated(session_token):
        raise HTTPException(status_code=401, detail="Não autorizado")
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO mikrotik_devices (name, ip, port, username, password) VALUES (?, ?, ?, ?, ?)",
              (name.strip(), ip.strip(), port, username.strip(), password.strip()))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/", status_code=303)

@app.get("/mikrotik/delete/{device_id}")
async def delete_mikrotik(device_id: int, session_token: str = Cookie(None)):
    if not is_authenticated(session_token):
        raise HTTPException(status_code=401, detail="Não autorizado")
        
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM mikrotik_devices WHERE id=?", (device_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/", status_code=303)



@app.get("/mikrotik/download")
async def download_backup(filename: str = Query(...), password: str = Query(...), session_token: str = Cookie(None)):
    if not is_authenticated(session_token):
        raise HTTPException(status_code=401, detail="Não autorizado")
        
    if password != ADMIN_PASSWORD:
        return RedirectResponse(url="/?msg=Senha+de+autorização+incorreta!", status_code=303)
    
    safe_filename = os.path.basename(filename)
    file_path = os.path.join("/app/backups", safe_filename)
    
    if not os.path.exists(file_path):
        return RedirectResponse(url="/?msg=Arquivo+de+backup+não+encontrado!", status_code=303)
        
    return FileResponse(file_path, filename=safe_filename, media_type="text/plain")


@app.get("/mikrotik/backup-now/{device_id}")
async def backup_now(device_id: int, session_token: str = Cookie(None)):
    if not is_authenticated(session_token):
        raise HTTPException(status_code=401, detail="Não autorizado")
        
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM mikrotik_devices WHERE id=?", (device_id,))
    dev = c.fetchone()
    conn.close()

    result_msg = "Dispositivo não encontrado."
    if dev:
        date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        clean_name = "".join(x for x in dev["name"] if x.isalnum() or x in ('_', '-'))
        filename = f"{clean_name}_{dev['ip']}_{date_str}"
        
        loop = asyncio.get_event_loop()
        success, msg = await loop.run_in_executor(
            None, backup_mikrotik_ssh, clean_name, dev["ip"], dev["port"], dev["username"], dev["password"], filename
        )
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        conn_update = get_db()
        c_up = conn_update.cursor()
        if success:
            c_up.execute("UPDATE mikrotik_devices SET last_backup=?, last_status='SUCCESS' WHERE id=?", (now, device_id))
            await send_telegram(f"✅ <b>[Backup Manual]</b>\nDispositivo: <b>{dev['name']}</b> ({dev['ip']})\nBackup manual executado com sucesso!")
        else:
            c_up.execute("UPDATE mikrotik_devices SET last_status=? WHERE id=?", (f"FAILED: {msg}", device_id))
            await send_telegram(f"❌ <b>[Falha no Backup Manual]</b>\nDispositivo: <b>{dev['name']}</b> ({dev['ip']})\nErro: <code>{msg}</code>")
        conn_update.commit()
        conn_update.close()
        
    return RedirectResponse(url="/", status_code=303)




if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
