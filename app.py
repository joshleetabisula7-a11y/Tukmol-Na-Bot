import os
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

BOT_TOKEN = "8568040647:AAGo6PjE_gHyooSLhuR_wfLHW5zziSPZVY8"

LOG_FILE = "logs.txt"   # Put your logs here


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Hello! I am your Keyword Search Bot.\n"
        "Use:\n"
        "/search <keyword> <max lines>\n\n"
        "Example:\n"
        "/search josh 100"
    )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📌 Available Commands:\n\n"
        "/start - Welcome message\n"
        "/help - Command list\n"
        "/search <keyword> <maxlines> - Search logs.txt\n\n"
        "Example:\n"
        "/search test 200"
    )


async def search(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if len(args) < 2:
        await update.message.reply_text("❌ Usage: /search <keyword> <maxlines>")
        return

    keyword = args[0]
    try:
        max_lines = int(args[1])
    except:
        await update.message.reply_text("❌ Maxlines must be a number.")
        return

    if max_lines > 300:
        max_lines = 300

    if not os.path.exists(LOG_FILE):
        await update.message.reply_text("❌ logs.txt not found on server.")
        return

    results = []
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if keyword.lower() in line.lower():
                results.append(line.strip())
                if len(results) >= max_lines:
                    break

    if not results:
        await update.message.reply_text("⚠️ No results found.")
        return

    output = "\n".join(results)
    result_filename = f"results_{keyword}.txt"

    with open(result_filename, "w", encoding="utf-8") as f:
        f.write(output)

    await update.message.reply_document(document=open(result_filename, "rb"))


def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("search", search))

    print("Bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()
