import aiohttp

from app.db import get_setting, get_db


async def send_telegram(message: str, dest_id: int = None):
    token = None
    chat_id = None
    
    if dest_id:
        conn = get_db()
        try:
            c = conn.cursor()
            c.execute("SELECT token, chat_id FROM telegram_destinations WHERE id=?", (dest_id,))
            row = c.fetchone()
            if row:
                token = row["token"]
                chat_id = row["chat_id"]
        finally:
            conn.close()
            
    if not token or not chat_id:
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
