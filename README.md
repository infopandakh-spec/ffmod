# Mod Key Shop (Flask + SQLite)

Telegram login · Admin stock · Resellers · Wallet top-up & instant pay (KHQR Pay: ABA + Bakong)

## Run
    pip install -r requirements.txt
    export $(grep -v '^#' .env | xargs)   # or set the variables yourself
    python app.py

Telegram Login needs HTTPS and `/setdomain` in @BotFather.

## First steps
1. Log in with the Telegram account listed in ADMIN_IDS.
2. /admin -> Payment: enter the KHQR Pay API key, press "Test /health".
3. Games: add each game (name + image PNG/JPG/WEBP, max 3 MB). Then add items: choose the game, duration in days (1/7/30) and the price per key, then paste keys (one per line). Each game+duration is one item with its own stock. Optional 'Setup' link/note per game appears as the Setup button in the dialog.
4. Have a user log in once, then set their role to reseller (discount % or per-mod price).

## Notes
- Game images are stored in `uploads/` (set UPLOAD_DIR). Keep this folder with shop.db when you back up.
- Payment key is stored in shop.db: protect that file.
- Pay now reserves keys for 10 minutes; unpaid reservations are released automatically.
- Revoke any bot token that was ever pasted in chat/screenshots.
- After-purchase guides (video, text, links, file) are stored in `guide_files/` (set GUIDE_DIR) and only buyers of that game can open them. Back it up together with shop.db.
