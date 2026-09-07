import aiohttp

from app.db import get_setting


async def send_telegram(message: str):
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
