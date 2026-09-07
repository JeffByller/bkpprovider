import asyncio
import datetime
import glob
import os
import time

import paramiko

from app.config import BACKUPS_DIR
from app.db import get_db, get_settings_typed
from app.telegram import send_telegram


def clean_device_name(name: str) -> str:
    return "".join(x for x in name if x.isalnum() or x in ("_", "-"))


def cleanup_old_backups(clean_name, ip, keep=7):
    try:
        prefix = f"{BACKUPS_DIR}/{clean_name}_{ip}_*.txt"
        files = glob.glob(prefix)
        files.sort()
        if len(files) > keep:
            for f in files[:-keep]:
                try:
                    if os.path.exists(f):
                        os.remove(f)
                except Exception as e:
                    print(f"[Backup Cleanup Error] {f}: {e}")
    except Exception as e:
        print(f"[Cleanup Error] {e}")


def backup_mikrotik_ssh(clean_name, ip, port, username, password, filename, retention=7):
    os.makedirs(BACKUPS_DIR, exist_ok=True)
    cleanup_old_backups(clean_name, ip, keep=max(retention - 1, 1))

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, port=port, username=username, password=password, timeout=10)

        remote_file_name = f"backup_{filename}"
        ssh.exec_command(f"/export file={remote_file_name}")
        time.sleep(3)

        sftp = ssh.open_sftp()
        local_path = f"{BACKUPS_DIR}/{filename}.txt"

        try:
            sftp.get(f"{remote_file_name}.rsc", local_path)
            remote_to_remove = f"{remote_file_name}.rsc"
        except Exception:
            sftp.get(remote_file_name, local_path)
            remote_to_remove = remote_file_name

        try:
            ssh.exec_command(f"/file remove {remote_to_remove}")
        except Exception:
            pass

        sftp.close()
        ssh.close()

        cleanup_old_backups(clean_name, ip, keep=retention)
        return True, "Backup realizado com sucesso!"
    except Exception as e:
        return False, str(e)


async def run_backup_for_device(dev, manual=False):
    dev_id = dev["id"]
    name = dev["name"]
    ip = dev["ip"]
    settings = get_settings_typed()

    date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_name = clean_device_name(name)
    filename = f"{clean_name}_{ip}_{date_str}"

    loop = asyncio.get_event_loop()
    success, msg = await loop.run_in_executor(
        None, backup_mikrotik_ssh, clean_name, ip, dev["port"], dev["username"],
        dev["password"], filename, settings["backup_retention"],
    )

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    try:
        c = conn.cursor()
        if success:
            c.execute("UPDATE mikrotik_devices SET last_backup=?, last_status='SUCCESS' WHERE id=?", (now, dev_id))
        else:
            c.execute("UPDATE mikrotik_devices SET last_status=? WHERE id=?", (f"FAILED: {msg}", dev_id))
        conn.commit()
    finally:
        conn.close()

    tag = "Manual" if manual else "Automático"
    if success:
        await send_telegram(f"✅ <b>[Backup {tag}]</b>\nDispositivo: <b>{name}</b> ({ip})\nBackup realizado com sucesso!")
    else:
        await send_telegram(f"❌ <b>[Falha no Backup {tag}]</b>\nDispositivo: <b>{name}</b> ({ip})\nErro: <code>{msg}</code>")

    return success, msg


async def run_all_backups():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM mikrotik_devices")
        devices = c.fetchall()
        conn.close()

        for dev in devices:
            await run_backup_for_device(dev, manual=False)
    except Exception as e:
        print(f"[Mikrotik Backup Error] {e}")


async def mikrotik_worker():
    last_executed_slot = None
    while True:
        try:
            settings = get_settings_typed()
            now = datetime.datetime.now()
            b_hour = settings.get("backup_hour", 17)
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

