#!/usr/bin/env python3
"""
app.py — Telegram Logs Search Bot with key system + admin key generation

Commands:
 - /start
 - /help
 - /unlock <key>
 - /lock
 - /search <keyword> <maxlines>   (requires unlocked)
 - /gen <days>                    (admin only) -> generates a key that expires in <days> days
 - /downloadkey                   (admin only) -> download keys.txt

Keys stored in keys.txt as:
KEY|YYYY-MM-DD

Admins (seeded): 7301067810, 8373854436

Requirements:
 pip install python-telegram-bot==20.3
"""
import os
import re
import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from telegram import Update, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

# -------- CONFIG --------
# BOT TOKEN (you previously provided this token). For production prefer env var.
BOT_TOKEN = "8568040647:AAHrjk2CnFeKJ0gYFZQp4mDCKd02nyyOii0"

LOG_FILE = "logs.txt"     # source for searches
KEYS_FILE = "keys.txt"    # stores keys created/available (KEY|YYYY-MM-DD)
ADMINS_FILE = "admins.json"  # optional admin persistence

# Seed admins (from your request)
SEED_ADMINS = {7301067810, 8373854436}

# Limits
MAX_LINES_LIMIT = 300

# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# runtime
sessions: Dict[int, Dict[str, Any]] = {}  # per-user session state
admins = set()  # runtime admin set

KEY_LINE_RE = re.compile(r'^([^|]+)\|?(\d{4}-\d{2}-\d{2})?$')  # key|YYYY-MM-DD optional

# ---------------- helpers ----------------

def load_admins():
    global admins
    admins = set(SEED_ADMINS)
    if os.path.exists(ADMINS_FILE):
        try:
            with open(ADMINS_FILE, "r", encoding="utf-8") as f:
                arr = json.load(f)
                for a in arr:
                    try:
                        admins.add(int(a))
                    except Exception:
                        logger.warning("Invalid admin id in admins.json: %s", a)
        except Exception as e:
            logger.exception("Failed to load admins.json: %s", e)
    logger.info("Admins: %s", admins)

def save_admins():
    try:
        with open(ADMINS_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(list(admins)), f)
    except Exception as e:
        logger.exception("Failed to save admins.json: %s", e)

def ensure_session(user_id: int):
    if user_id not in sessions:
        sessions[user_id] = {
            "unlocked": False,
            "used_key": None,
        }
    return sessions[user_id]

def parse_keys_file() -> List[Dict[str, Optional[datetime]]]:
    """Return list of {key: str, expires: datetime|None, raw: str}"""
    entries = []
    if not os.path.exists(KEYS_FILE):
        return entries
    try:
        with open(KEYS_FILE, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                m = KEY_LINE_RE.match(ln)
                if not m:
                    # try splitting by | and trimming
                    parts = [p.strip() for p in ln.split("|")]
                    key = parts[0] if parts else ln
                    expires = None
                    if len(parts) >= 2:
                        try:
                            expires = datetime.strptime(parts[1], "%Y-%m-%d")
                        except Exception:
                            expires = None
                    entries.append({"key": key, "expires": expires, "raw": ln})
                else:
                    key = m.group(1).strip()
                    exp_s = m.group(2)
                    expires = None
                    if exp_s:
                        try:
                            expires = datetime.strptime(exp_s, "%Y-%m-%d")
                        except Exception:
                            expires = None
                    entries.append({"key": key, "expires": expires, "raw": ln})
    except Exception as e:
        logger.exception("Failed to read keys.txt: %s", e)
    return entries

def is_key_valid(key: str) -> (bool, Optional[str]):
    """Return (True, None) if key exists and not expired; otherwise (False, reason)."""
    key = key.strip()
    items = parse_keys_file()
    for it in items:
        if it["key"] == key:
            if it["expires"] and it["expires"].date() < datetime.utcnow().date():
                return False, f"expired on {it['expires'].date().isoformat()}"
            return True, None
    return False, "not found"

def generate_key(days: int) -> Dict[str, Any]:
    """Generate a key, append to keys.txt, return dict with key and expiry."""
    days = max(1, int(days))
    key = secrets.token_urlsafe(12).replace("=", "")  # compact key
    expiry = (datetime.utcnow().date() + timedelta(days=days))
    line = f"{key}|{expiry.isoformat()}\n"
    try:
        with open(KEYS_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:
        logger.exception("Failed to append to keys.txt: %s", e)
        raise
    return {"key": key, "expires": expiry}

def admin_only(user_id: int) -> bool:
    return user_id in admins

# ---------------- Commands ----------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    ensure_session(uid)
    msg = (
        "👋 Logs Search Bot with Key Access\n\n"
        "Commands:\n"
        "/unlock <key> - unlock bot (required before /search)\n"
        "/lock - lock your session\n"
        "/search <keyword> <maxlines> - search logs.txt (max 300 lines)\n\n"
        "Admin commands:\n"
        "/gen <days> - generate a new key (admin only)\n"
        "/downloadkey - download keys.txt (admin only)\n"
        "/help - this message\n"
    )
    await update.message.reply_text(msg)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await start(update, context)

async def unlock_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    sess = ensure_session(uid)
    args = context.args
    if not args:
        await update.message.reply_text("Usage: /unlock <key>")
        return
    key = " ".join(args).strip()
    ok, reason = is_key_valid(key)
    if ok:
        sess["unlocked"] = True
        sess["used_key"] = key
        await update.message.reply_text(f"🔓 Unlocked — access granted. (Key: {key[:4]}... )")
    else:
        await update.message.reply_text(f"Key invalid: {reason}")

async def lock_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    sess = ensure_session(uid)
    sess["unlocked"] = False
    sess["used_key"] = None
    await update.message.reply_text("🔒 Locked. Use /unlock <key> to unlock again.")

async def search_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    sess = ensure_session(uid)
    if not sess.get("unlocked", False):
        await update.message.reply_text("❗ You must unlock first with /unlock <key> before using /search.")
        return

    args = context.args
    if len(args) < 2:
        await update.message.reply_text("Usage: /search <keyword> <maxlines> (max 300)")
        return
    keyword = args[0].strip()
    try:
        maxlines = int(args[1])
    except ValueError:
        await update.message.reply_text("Maxlines must be an integer (1..300).")
        return
    if maxlines < 1:
        maxlines = 1
    if maxlines > MAX_LINES_LIMIT:
        maxlines = MAX_LINES_LIMIT

    if not os.path.exists(LOG_FILE):
        await update.message.reply_text("logs.txt not found on server.")
        return

    found = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if keyword.lower() in line.lower():
                    if line.strip() not in found:
                        found.append(line.rstrip("\n"))
                    if len(found) >= maxlines:
                        break
    except Exception as e:
        logger.exception("Search failed: %s", e)
        await update.message.reply_text("Search failed: " + str(e))
        return

    if not found:
        await update.message.reply_text("No results found.")
        return

    # write temporary file and send
    filename = f"results_{keyword}_{uid}.txt"
    try:
        with open(filename, "w", encoding="utf-8") as out:
            out.write("\n".join(found))
        await update.message.reply_document(document=open(filename, "rb"))
    finally:
        try:
            if os.path.exists(filename):
                os.remove(filename)
        except Exception:
            pass

async def gen_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not admin_only(uid):
        await update.message.reply_text("Only admins can generate keys.")
        return
    args = context.args
    if not args:
        await update.message.reply_text("Usage: /gen <days>  (e.g. /gen 30)")
        return
    try:
        days = int(args[0])
    except ValueError:
        await update.message.reply_text("Days must be an integer (number of days until expiry).")
        return
    try:
        info = generate_key(days)
    except Exception as e:
        await update.message.reply_text("Failed to generate key: " + str(e))
        return
    await update.message.reply_text(f"🔑 Generated key: `{info['key']}` (expires {info['expires'].isoformat()})", parse_mode="Markdown")

async def downloadkey_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not admin_only(uid):
        await update.message.reply_text("Only admins can download keys.")
        return
    if not os.path.exists(KEYS_FILE):
        await update.message.reply_text("No keys.txt file exists yet.")
        return
    try:
        await update.message.reply_document(document=InputFile(KEYS_FILE))
    except Exception as e:
        logger.exception("Failed to send keys.txt: %s", e)
        await update.message.reply_text("Failed to send keys.txt: " + str(e))

async def addadmin_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin convenience: /addadmin <numeric_user_id>"""
    uid = update.effective_user.id
    if not admin_only(uid):
        await update.message.reply_text("Only admins can add admins.")
        return
    args = context.args
    if not args:
        await update.message.reply_text("Usage: /addadmin <numeric_user_id>")
        return
    try:
        new_id = int(args[0])
        admins.add(new_id)
        save_admins()
        await update.message.reply_text(f"Added admin: {new_id}")
    except Exception as e:
        await update.message.reply_text("Invalid id or error: " + str(e))

async def removeadmin_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not admin_only(uid):
        await update.message.reply_text("Only admins can remove admins.")
        return
    args = context.args
    if not args:
        await update.message.reply_text("Usage: /removeadmin <numeric_user_id>")
        return
    try:
        rem = int(args[0])
        if rem in admins:
            admins.remove(rem)
            save_admins()
            await update.message.reply_text(f"Removed admin: {rem}")
        else:
            await update.message.reply_text("That id is not an admin.")
    except Exception as e:
        await update.message.reply_text("Invalid id or error: " + str(e))

async def listadmins_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not admin_only(uid):
        await update.message.reply_text("Only admins.")
        return
    await update.message.reply_text("Admins: " + ", ".join(str(x) for x in sorted(admins)))

# ---------------- entrypoint ----------------

def main():
    # load admins from seed + file
    load_admins()

    if not BOT_TOKEN:
        logger.error("BOT_TOKEN not set.")
        return

    app = ApplicationBuilder().token(BOT_TOKEN).build()

    # basic commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("unlock", unlock_cmd))
    app.add_handler(CommandHandler("lock", lock_cmd))
    app.add_handler(CommandHandler("search", search_cmd))

    # admin commands
    app.add_handler(CommandHandler("gen", gen_cmd))
    app.add_handler(CommandHandler("downloadkey", downloadkey_cmd))
    app.add_handler(CommandHandler("addadmin", addadmin_cmd))
    app.add_handler(CommandHandler("removeadmin", removeadmin_cmd))
    app.add_handler(CommandHandler("listadmins", listadmins_cmd))

    logger.info("Bot starting (polling)...")
    app.run_polling()

if __name__ == "__main__":
    main()
