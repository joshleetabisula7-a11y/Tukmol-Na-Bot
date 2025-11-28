#!/usr/bin/env python3
"""
Telegram Logs Search Bot — Key-protected, admin tools, anti-duplicate results.

Files used (in repo root):
- app.py              (this file)
- logs.txt            (source logs to search when user hasn't uploaded a file)
- keys.txt            (key|YYYY-MM-DD lines; created by /gen)
- users.json          (auto-created: list of known user ids)
- admins.json         (auto-created; seeded with provided IDs)
- seen.json           (auto-created: globally-seen lines — prevents duplicates across users)

Commands:
- /start
- /help
- /search <keyword> <maxlines>   # requires redeemed key
- /redeem <key>                  # redeem a key to gain access
Admin-only:
- /gen <days>                    # generate a key valid for <days>
- /downloadkey                   # download keys.txt
- /announce <message>            # send message to all known users

Requirements:
  pip install python-telegram-bot==20.3
"""
import os
import re
import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, List, Set, Optional

from telegram import Update, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

# -------- CONFIG ----------
BOT_TOKEN = "8568040647:AAHrjk2CnFeKJ0gYFZQp4mDCKd02nyyOii0"  # your token
LOG_FILE = "logs.txt"
KEYS_FILE = "keys.txt"
USERS_FILE = "users.json"
ADMINS_FILE = "admins.json"
SEEN_FILE = "seen.json"
UPLOAD_TMP = "/tmp"
MAX_ALLOWED_LINES = 300

# Seed admins (from your request)
SEED_ADMINS = [7301067810, 8373854436]

# -------- logging ----------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# -------- runtime state (in-memory) ----------
EMAIL_REGEX = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
users_set: Set[int] = set()
admins_set: Set[int] = set()
seen_lines: Set[str] = set()   # global dedupe (persisted)
redeemed: Dict[int, str] = {}  # user_id -> expiry ISOdate string (persisted? We keep in memory and store to users.json)

# ---------- Helpers: persistence ----------
def safe_load_json(path: str, default):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.exception("Failed loading %s: %s", path, e)
    return default

def save_json(path: str, content):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(content, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.exception("Failed saving %s: %s", path, e)

def load_state():
    global users_set, admins_set, seen_lines
    users = safe_load_json(USERS_FILE, [])
    users_set = set(int(x) for x in users)
    admins = safe_load_json(ADMINS_FILE, [])
    if not admins:
        admins = SEED_ADMINS
    admins_set = set(int(x) for x in admins)
    # ensure seeds
    admins_set.update(SEED_ADMINS)
    save_json(ADMINS_FILE, sorted(list(admins_set)))
    seen = safe_load_json(SEEN_FILE, [])
    seen_lines = set(seen)

def persist_users_and_redeemed():
    # Persist known users plus redeemed info for convenience
    try:
        data = {"users": sorted(list(users_set))}
        # Note: redeemed stored under 'redeemed' mapping user -> expiry
        if redeemed:
            data["redeemed"] = redeemed
        save_json(USERS_FILE, data)
    except Exception as e:
        logger.exception("persist users failed: %s", e)

def persist_seen():
    try:
        save_json(SEEN_FILE, sorted(list(seen_lines)))
    except Exception as e:
        logger.exception("persist seen failed: %s", e)

# ---------- Keys handling ----------
def parse_keys_file() -> List[Dict[str, Any]]:
    out = []
    if not os.path.exists(KEYS_FILE):
        return out
    try:
        with open(KEYS_FILE, "r", encoding="utf-8") as f:
            for ln in f:
                line = ln.strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split("|", 1)]
                key = parts[0]
                expires = None
                if len(parts) > 1:
                    try:
                        expires = datetime.strptime(parts[1], "%Y-%m-%d").date()
                    except Exception:
                        expires = None
                out.append({"key": key, "expires": expires, "raw": line})
    except Exception as e:
        logger.exception("Failed to parse keys.txt: %s", e)
    return out

def append_key_to_file(key: str, expire_date: datetime.date):
    line = f"{key}|{expire_date.isoformat()}\n"
    with open(KEYS_FILE, "a", encoding="utf-8") as f:
        f.write(line)

def generate_key(days: int) -> Dict[str, Any]:
    key = secrets.token_urlsafe(12)  # readable, URL safe
    expire_date = (datetime.utcnow().date() + timedelta(days=days))
    append_key_to_file(key, expire_date)
    return {"key": key, "expires": expire_date}

def find_key_entry(key: str) -> Optional[Dict[str, Any]]:
    for e in parse_keys_file():
        if e["key"] == key:
            return e
    return None

def is_key_expired(entry: Dict[str, Any]) -> bool:
    if not entry or not entry.get("expires"):
        return False
    return datetime.utcnow().date() > entry["expires"]

# ---------- user & access helpers ----------
def add_user(uid: int):
    if uid not in users_set:
        users_set.add(uid)
        persist_users_and_redeemed()

def user_has_access(uid: int) -> bool:
    # admin always has access
    if uid in admins_set:
        return True
    # check redeemed dict for expiry
    val = redeemed.get(uid)
    if not val:
        return False
    try:
        exp = datetime.strptime(val, "%Y-%m-%d").date()
        return datetime.utcnow().date() <= exp
    except Exception:
        return False

def redeem_for_user(uid: int, key: str) -> (bool, str):
    entry = find_key_entry(key)
    if not entry:
        return False, "not_found"
    if is_key_expired(entry):
        return False, "expired"
    # give user access until entry.expires
    expiry = entry.get("expires")
    expiry_iso = expiry.isoformat() if expiry else ""
    redeemed[uid] = expiry_iso
    persist_users_and_redeemed()
    return True, expiry_iso

# ---------- Bot command handlers ----------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    add_user(user.id)
    text = (
        "Hello — Logs Search Bot with key protection.\n\n"
        "You must redeem a key before using /search.\n"
        "Commands:\n"
        "/redeem <key> - redeem your key\n"
        "/search <keyword> <maxlines> - search logs (max 300)\n\n"
        "Admins can use /gen, /downloadkey, /announce\n"
    )
    await update.message.reply_text(text)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "/start - hello\n"
        "/help - this help\n"
        "/redeem <key> - redeem a key to gain access\n"
        "/search <keyword> <maxlines> - run a search (needs redeemed key)\n\n"
        "Admin only:\n"
        "/gen <days> - generate key valid for days\n"
        "/downloadkey - download keys.txt\n"
        "/announce <msg> - broadcast message to all users\n"
    )

async def redeem_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    add_user(user.id)
    args = context.args
    if not args:
        await update.message.reply_text("Usage: /redeem <key>")
        return
    key = args[0].strip()
    ok, info = redeem_for_user(user.id, key)
    if ok:
        await update.message.reply_text(f"Key accepted. Access granted until {info}. You can now use /search.")
    else:
        if info == "not_found":
            await update.message.reply_text("Incorrect Key Or Expired Please Renew again")
        elif info == "expired":
            await update.message.reply_text("Key found but expired.")
        else:
            await update.message.reply_text("Key rejected.")

async def search_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    add_user(user.id)
    if not user_has_access(user.id):
        await update.message.reply_text("Locked — redeem a key first with /redeem <key>")
        return

    args = context.args
    if len(args) < 2:
        await update.message.reply_text("Usage: /search <keyword> <maxlines>")
        return
    keyword = args[0]
    try:
        max_lines = int(args[1])
    except ValueError:
        await update.message.reply_text("Maxlines must be a number.")
        return
    if max_lines > MAX_ALLOWED_LINES:
        max_lines = MAX_ALLOWED_LINES
    if not os.path.exists(LOG_FILE):
        await update.message.reply_text("logs.txt not found on server.")
        return

    results: List[str] = []
    added = 0
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.rstrip("\n")
                # skip globally seen lines
                if line in seen_lines:
                    continue
                # per-search dedupe
                if line in results:
                    continue
                if keyword.lower() in line.lower():
                    results.append(line)
                    seen_lines.add(line)  # mark globally so nobody else receives again
                    added += 1
                    if added >= max_lines:
                        break
        # persist seen lines (so duplicates don't reappear after restart)
        persist_seen()
        if not results:
            await update.message.reply_text("No results found (subject to dedupe/filters).")
            return
        # send a small preview then file
        preview = "\n".join(results[:10])
        await update.message.reply_text(f"Found {len(results)} results. Preview:\n\n{preview}")
        # write and send file
        fname = f"results_{user.id}_{int(datetime.utcnow().timestamp())}.txt"
        path = os.path.join(UPLOAD_TMP, fname)
        with open(path, "w", encoding="utf-8") as out:
            out.write("\n".join(results))
        await context.bot.send_document(chat_id=user.id, document=InputFile(path, filename=f"results_{keyword}.txt"))
        try:
            os.remove(path)
        except Exception:
            pass
    except Exception as e:
        logger.exception("Search error: %s", e)
        await update.message.reply_text("Search failed: " + str(e))

# ---------- Admin commands ----------
def is_admin(uid: int) -> bool:
    return uid in admins_set

async def gen_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_admin(user.id):
        await update.message.reply_text("Only admins can run this.")
        return
    args = context.args
    if not args:
        await update.message.reply_text("Usage: /gen <days>")
        return
    try:
        days = int(args[0])
    except ValueError:
        await update.message.reply_text("Days must be an integer.")
        return
    if days <= 0:
        await update.message.reply_text("Days must be positive.")
        return
    entry = generate_key(days)
    await update.message.reply_text(f"Generated key: `{entry['key']}` (expires {entry['expires'].isoformat()})", parse_mode="Markdown")

async def downloadkey_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_admin(user.id):
        await update.message.reply_text("Only admins.")
        return
    if not os.path.exists(KEYS_FILE):
        await update.message.reply_text("No keys.txt found.")
        return
    try:
        await context.bot.send_document(chat_id=user.id, document=InputFile(KEYS_FILE))
    except Exception as e:
        logger.exception("downloadkey failed: %s", e)
        await update.message.reply_text("Failed to send keys file: " + str(e))

async def announce_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_admin(user.id):
        await update.message.reply_text("Only admins.")
        return
    message = " ".join(context.args).strip()
    if not message:
        await update.message.reply_text("Usage: /announce <message>")
        return
    sent = 0
    failures = 0
    add_user(user.id)  # ensure admin included in users list
    persist_users_and_redeemed()
    for uid in sorted(users_set):
        try:
            await context.bot.send_message(chat_id=uid, text=f"📢 Announcement:\n\n{message}")
            sent += 1
        except Exception as e:
            failures += 1
    await update.message.reply_text(f"Announcement sent to {sent} users, {failures} failures.")

# ---------- startup ----------
def ensure_files_exist():
    # create placeholder files if missing
    if not os.path.exists(KEYS_FILE):
        open(KEYS_FILE, "a", encoding="utf-8").close()
    if not os.path.exists(USERS_FILE):
        save_json(USERS_FILE, [])
    if not os.path.exists(ADMINS_FILE):
        save_json(ADMINS_FILE, SEED_ADMINS)
    if not os.path.exists(SEEN_FILE):
        save_json(SEEN_FILE, [])

def main():
    ensure_files_exist()
    load_state()

    # build application
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    # public commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("redeem", redeem_cmd))
    app.add_handler(CommandHandler("search", search_cmd))

    # admin commands
    app.add_handler(CommandHandler("gen", gen_cmd))
    app.add_handler(CommandHandler("downloadkey", downloadkey_cmd))
    app.add_handler(CommandHandler("announce", announce_cmd))

    logger.info("Bot starting (polling)...")
    app.run_polling()

if __name__ == "__main__":
    main()        sessions[user_id] = {
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
