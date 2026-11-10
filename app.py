"""Mod Key Shop - Flask + SQLite
Telegram login, Admin stock entry, Reseller pricing + wallet.

Run:
    pip install flask
    export BOT_TOKEN=123:ABC  BOT_USERNAME=MyShopBot  ADMIN_IDS=11111111  SECRET_KEY=change-me
    python app.py
Telegram Login Widget requires HTTPS + the domain set via @BotFather /setdomain.
For local testing set DEV_LOGIN=1 to get a fake-login form (never in production).
"""
import csv, hashlib, hmac, io, json, os, re, secrets, sqlite3, time
import urllib.error, urllib.request
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect,
                   render_template, request, send_from_directory, session, url_for)
from jinja2 import DictLoader

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "YourBot")
ADMIN_IDS = {int(x) for x in os.environ.get("ADMIN_IDS", "").split(",") if x.strip()}
DEV_LOGIN = os.environ.get("DEV_LOGIN") == "1"
DB_PATH = os.environ.get("DB_PATH", "shop.db")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "uploads")
GUIDE_DIR = os.environ.get("GUIDE_DIR", "guide_files")  # after-purchase videos/files: buyers only

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  MAX_CONTENT_LENGTH=32 * 1024 * 1024)  # images <=3 MB, promo videos <=30 MB (checked per upload)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, telegram_id INTEGER UNIQUE NOT NULL, username TEXT,
  first_name TEXT, role TEXT NOT NULL DEFAULT 'user',
  discount_pct REAL NOT NULL DEFAULT 0, balance REAL NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS games(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, image TEXT,
  active INTEGER NOT NULL DEFAULT 1, setup TEXT);
CREATE TABLE IF NOT EXISTS mods(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '',
  price REAL NOT NULL, active INTEGER NOT NULL DEFAULT 1, game_id INTEGER,
  duration_days INTEGER, duration_unit TEXT DEFAULT 'day');
CREATE TABLE IF NOT EXISTS reseller_prices(
  user_id INTEGER, mod_id INTEGER, price REAL, PRIMARY KEY(user_id, mod_id));
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY, user_id INTEGER, mod_id INTEGER, qty INTEGER,
  total REAL, buyer_role TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS keys(
  id INTEGER PRIMARY KEY, mod_id INTEGER NOT NULL, key_value TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'available', order_id INTEGER, checkout_id INTEGER,
  UNIQUE(mod_id, key_value));
CREATE TABLE IF NOT EXISTS checkouts(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, mod_id INTEGER NOT NULL,
  qty INTEGER NOT NULL, total REAL NOT NULL, rail TEXT NOT NULL, payment_id TEXT,
  status TEXT NOT NULL DEFAULT 'Pending', qr_image TEXT, checkout_url TEXT,
  expires_at TEXT, order_id INTEGER, created_at INTEGER);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS guides(
  game_id INTEGER PRIMARY KEY, text TEXT, links TEXT, video TEXT, file TEXT, file_name TEXT);
CREATE TABLE IF NOT EXISTS topups(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, rail TEXT NOT NULL,
  amount REAL NOT NULL, payment_id TEXT, status TEXT NOT NULL DEFAULT 'Pending',
  qr_image TEXT, checkout_url TEXT, expires_at TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS transactions(
  id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL, type TEXT, ref TEXT,
  created_at INTEGER);
"""


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, isolation_level=None)  # manual txns
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    c = sqlite3.connect(DB_PATH)
    c.executescript(SCHEMA)
    for ddl in ("ALTER TABLE keys ADD COLUMN checkout_id INTEGER",  # upgrade an older database
                "ALTER TABLE mods ADD COLUMN game_id INTEGER",
                "ALTER TABLE mods ADD COLUMN duration_days INTEGER",
                "ALTER TABLE mods ADD COLUMN duration_unit TEXT DEFAULT 'day'",
                "ALTER TABLE games ADD COLUMN setup TEXT"):
        try:
            c.execute(ddl)
        except sqlite3.OperationalError:
            pass
    c.close()


# ---------- auth ----------
def verify_telegram(data):
    data = dict(data)
    their_hash = data.pop("hash", "")
    check = "\n".join(f"{k}={data[k]}" for k in sorted(data))
    secret = hashlib.sha256(BOT_TOKEN.encode()).digest()
    mine = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    try:
        fresh = time.time() - int(data.get("auth_date", 0)) < 86400
    except ValueError:
        fresh = False
    return bool(BOT_TOKEN) and fresh and hmac.compare_digest(mine, their_hash)


def login_user(tg_id, username, first_name):
    d = db()
    d.execute("INSERT OR IGNORE INTO users(telegram_id,username,first_name) VALUES(?,?,?)",
              (tg_id, username, first_name))
    d.execute("UPDATE users SET username=?, first_name=? WHERE telegram_id=?",
              (username, first_name, tg_id))
    if tg_id in ADMIN_IDS:  # admins are defined by Telegram ID, not username
        d.execute("UPDATE users SET role='admin' WHERE telegram_id=?", (tg_id,))
    u = d.execute("SELECT * FROM users WHERE telegram_id=?", (tg_id,)).fetchone()
    if not u["active"]:
        abort(403, "Account suspended")
    session.clear()
    session["uid"] = u["id"]
    session["csrf"] = secrets.token_hex(16)


@app.route("/auth/telegram")
def auth_telegram():
    if not verify_telegram(request.args):
        abort(403, "Telegram verification failed")
    a = request.args
    login_user(int(a["id"]), a.get("username", ""), a.get("first_name", ""))
    return redirect(url_for("shop"))


@app.route("/dev-login", methods=["GET", "POST"])
def dev_login():
    if not DEV_LOGIN:
        abort(404)
    if request.method == "POST":
        login_user(int(request.form["tg_id"]), request.form.get("name", "dev"), "Dev")
        return redirect(url_for("shop"))
    return render_template("dev.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("shop"))


@app.before_request
def load_user():
    g.user = None
    if "uid" in session:
        g.user = db().execute("SELECT * FROM users WHERE id=? AND active=1",
                              (session["uid"],)).fetchone()
    if request.method == "POST":  # CSRF
        if not g.user or not hmac.compare_digest(
                request.form.get("csrf", ""), session.get("csrf", "")):
            if request.endpoint != "dev_login":
                abort(400, "Bad CSRF token")


@app.context_processor
def inject():
    lang = session.get("lang", "kh")
    return dict(me=g.user, csrf=session.get("csrf", ""),
                bot=BOT_USERNAME, dev=DEV_LOGIN, lang=lang,
                t=lambda k: I18N.get(lang, {}).get(k) or I18N["en"].get(k, k),
                tv=tv, mtitle=mtitle,
                L={**I18N["en"], **I18N.get(lang, {})},
                tg_channel=get_setting("tg_channel"), tg_support=get_setting("tg_support"),
                site_name=get_setting("site_name") or "MASTER KH SHOP",
                brand_video=video_src(get_setting("brand_video")),
                brand_key=get_setting("brand_key") != "0")


I18N = {
    "en": {"shop": "Shop", "topup": "Top up", "account": "My account", "orders": "Orders",
           "history": "Transactions", "admin": "Admin", "logout": "Logout", "balance": "Balance",
           "language": "Language", "channel": "Channel", "support": "Support",
           "topup_title": "Top up balance", "pay_khqr": "Pay with KHQR", "time": "Time",
           "type": "Type", "amount": "Amount", "no_tx": "No transactions yet.",
           "no_topup": "No top-ups yet.", "topup_reqs": "Top-up requests", "role": "Role",
           "spent": "Total spent", "my_orders": "My orders"},
    "kh": {"shop": "ហាង", "topup": "បញ្ចូលប្រាក់", "account": "គណនីរបស់ខ្ញុំ", "orders": "ការបញ្ជាទិញ",
           "history": "ប្រវត្តិប្រតិបត្តិការ", "admin": "អ្នកគ្រប់គ្រង", "logout": "ចាកចេញ", "balance": "សមតុល្យ",
           "language": "ភាសា", "channel": "ឆានែល", "support": "ជំនួយ",
           "topup_title": "បញ្ចូលប្រាក់ចូលគណនី", "pay_khqr": "បង់ជាមួយ KHQR", "time": "ពេលវេលា",
           "type": "ប្រភេទ", "amount": "ចំនួន", "no_tx": "មិនទាន់មានប្រតិបត្តិការទេ។",
           "no_topup": "មិនទាន់មានការបញ្ចូលប្រាក់ទេ។", "topup_reqs": "សំណើបញ្ចូលប្រាក់", "role": "តួនាទី",
           "spent": "ចំណាយសរុប", "my_orders": "ការបញ្ជាទិញរបស់ខ្ញុំ"},
}

I18N["en"].update({
 "gen_title": "Generate new keys",
 "login_buy": "Login with Telegram to buy.",
 "from": "From",
 "in_stock": "in stock",
 "sold_out": "Sold out",
 "gen_keys": "Generate keys",
 "no_games": "No games yet.",
 "keys_count": "Keys count",
 "game": "Game",
 "duration": "Duration",
 "pay_with": "Pay with",
 "setup": "Setup",
 "generate": "Generate",
 "total": "Total",
 "per_key": "per key",
 "no_stock": "No stock",
 "login_first": "Login with Telegram first",
 "enter_count": "Enter keys count",
 "only_stock": "Only {n} in stock",
 "max_qty": "Max {n} keys per order",
 "not_enough": "Not enough balance. Top up or choose another payment.",
 "order": "Order",
 "how_to_use": "How to use",
 "watch_video": "Watch video",
 "mod": "Item",
 "qty": "Qty",
 "export_csv": "Export CSV",
 "discount": "discount",
 "pay_na": "Payment is not available yet.",
 "pay": "Pay",
 "scan": "Scan with ABA / any Bakong app. Valid 10 minutes.",
 "open_checkout": "Open checkout page",
 "waiting": "Waiting for payment...",
 "status": "Status",
 "back": "Back",
 "back_shop": "Back to shop",
 "paid_ok": "Payment received. Balance updated.",
 "mismatch": "Amount mismatch - contact admin.",
 "scan2": "Scan with ABA / any Bakong app. Keys are held for you for 10 minutes.",
 "view_keys": "View your keys",
 "mismatch2": "Amount mismatch - contact admin with your payment.",
 "qr_new": "QR {s}. Create a new one.",
 "qr_retry": "QR {s}. Please try again.",
 "st_Pending": "Pending",
 "st_Paid": "Paid",
 "st_Expired": "Expired",
 "st_Failed": "Failed",
 "st_UnderPaid": "Underpaid",
 "tx_purchase": "Purchase",
 "tx_topup": "Top-up",
 "tx_direct_pay": "Direct payment",
 "role_user": "Customer",
 "role_reseller": "Reseller",
 "role_admin": "Admin",
 "err_qty": "Invalid quantity",
 "err_nomod": "Item not found",
 "err_balance": "Insufficient balance (need {n})",
 "err_stock": "Not enough stock",
 "err_pay": "Invalid payment method or quantity",
 "err_range": "Amount out of range for KHQR",
 "err_topup": "Choose a payment method and an amount between 0.01 and 500",
 "err_qr": "Could not create QR",
 "copy": "Copy",
 "unit_Hour": "Hour",
 "unit_Day": "Day",
 "unit_Month": "Month"
})
I18N["kh"].update({
 "gen_title": "បង្កើត Key ថ្មី",
 "login_buy": "ចូលតាម Telegram ដើម្បីទិញ។",
 "from": "ចាប់ពី",
 "in_stock": "ក្នុងស្តុក",
 "sold_out": "អស់ស្តុក",
 "gen_keys": "បង្កើត Key",
 "no_games": "មិនទាន់មានហ្គេមទេ។",
 "keys_count": "ចំនួន Key",
 "game": "ហ្គេម",
 "duration": "រយៈពេល",
 "pay_with": "បង់ជាមួយ",
 "setup": "ការដំឡើង",
 "generate": "បង្កើត",
 "total": "សរុប",
 "per_key": "ក្នុងមួយ Key",
 "no_stock": "អស់ស្តុក",
 "login_first": "សូមចូលតាម Telegram សិន",
 "enter_count": "ដាក់ចំនួន Key",
 "only_stock": "នៅសល់ត្រឹម {n} ក្នុងស្តុក",
 "max_qty": "អតិបរមា {n} Key ក្នុងមួយការបញ្ជាទិញ",
 "not_enough": "សមតុល្យមិនគ្រប់គ្រាន់ សូមបញ្ចូលប្រាក់ ឬជ្រើសវិធីបង់ផ្សេង។",
 "order": "ការបញ្ជាទិញ",
 "how_to_use": "របៀបប្រើ",
 "watch_video": "មើលវីដេអូ",
 "mod": "ទំនិញ",
 "qty": "ចំនួន",
 "export_csv": "នាំចេញ CSV",
 "discount": "បញ្ចុះតម្លៃ",
 "pay_na": "មិនទាន់អាចបង់ប្រាក់បានទេ។",
 "pay": "បង់",
 "scan": "ស្កេនជាមួយ ABA ឬកម្មវិធី Bakong ណាមួយ។ មានសុពលភាព ១០ នាទី។",
 "open_checkout": "បើកទំព័របង់ប្រាក់",
 "waiting": "កំពុងរង់ចាំការបង់ប្រាក់...",
 "status": "ស្ថានភាព",
 "back": "ត្រឡប់ក្រោយ",
 "back_shop": "ត្រឡប់ទៅហាង",
 "paid_ok": "បានទទួលការបង់ប្រាក់ សមតុល្យត្រូវបានធ្វើបច្ចុប្បន្នភាព។",
 "mismatch": "ចំនួនទឹកប្រាក់មិនត្រូវគ្នា សូមទាក់ទងអ្នកគ្រប់គ្រង។",
 "scan2": "ស្កេនជាមួយ ABA ឬកម្មវិធី Bakong ណាមួយ។ Key ត្រូវបានរក្សាទុកឱ្យអ្នកក្នុងរយៈពេល ១០ នាទី។",
 "view_keys": "មើល Key របស់អ្នក",
 "mismatch2": "ចំនួនទឹកប្រាក់មិនត្រូវគ្នា សូមទាក់ទងអ្នកគ្រប់គ្រងជាមួយភស្តុតាងបង់ប្រាក់។",
 "qr_new": "QR {s} សូមបង្កើតថ្មី។",
 "qr_retry": "QR {s} សូមព្យាយាមម្តងទៀត។",
 "st_Pending": "កំពុងរង់ចាំ",
 "st_Paid": "បានបង់",
 "st_Expired": "ផុតកំណត់",
 "st_Failed": "បរាជ័យ",
 "st_UnderPaid": "បង់មិនគ្រប់",
 "tx_purchase": "ការទិញ",
 "tx_topup": "បញ្ចូលប្រាក់",
 "tx_direct_pay": "បង់ផ្ទាល់",
 "role_user": "អតិថិជន",
 "role_reseller": "អ្នកលក់ដុំ",
 "role_admin": "អ្នកគ្រប់គ្រង",
 "err_qty": "ចំនួនមិនត្រឹមត្រូវ",
 "err_nomod": "រកមិនឃើញទំនិញ",
 "err_balance": "សមតុល្យមិនគ្រប់ (ត្រូវការ {n})",
 "err_stock": "ស្តុកមិនគ្រប់",
 "err_pay": "វិធីបង់ប្រាក់ ឬចំនួនមិនត្រឹមត្រូវ",
 "err_range": "ចំនួនទឹកប្រាក់ហួសកម្រិតសម្រាប់ KHQR",
 "err_topup": "ជ្រើសវិធីបង់ប្រាក់ និងចំនួនចន្លោះ 0.01 ដល់ 500",
 "err_qr": "មិនអាចបង្កើត QR បានទេ",
 "copy": "ចម្លង",
 "unit_Hour": "ម៉ោង",
 "unit_Day": "ថ្ងៃ",
 "unit_Month": "ខែ"
})


def cur_lang():
    return session.get("lang", "kh")


def tr(key, **kw):
    """Server-side translation in the visitor's language (flash messages etc.)."""
    msg = I18N.get(cur_lang(), {}).get(key) or I18N["en"].get(key, key)
    return msg.format(**kw) if kw else msg


def tv(prefix, val):
    """Translate a status/type/role value; unknown values are shown as they are."""
    return I18N.get(cur_lang(), {}).get(prefix + str(val)) or I18N["en"].get(prefix + str(val)) or val


def mtitle(o):
    """Item title in the visitor's language: '<Game> 1 Day' becomes '<Game> 1 ថ្ងៃ' in Khmer."""
    k = o.keys()
    if "duration_days" in k and o["duration_days"] and "game_name" in k and o["game_name"]:
        return f"{o['game_name']} {dur_label(o)}"
    return o["name"]



@app.route("/lang/<code>")
def set_lang(code):
    if code in I18N:
        session["lang"] = code
    ref = request.referrer or ""
    # only redirect back to our own site
    if ref.startswith(request.host_url):
        return redirect(ref)
    return redirect(url_for("shop"))


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user:
            return redirect(url_for("shop"))
        return f(*a, **k)
    return w


def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if g.user["role"] != "admin":
            abort(403)
        return f(*a, **k)
    return w


@app.route("/admin/links", methods=["POST"])
@admin_required
def admin_links():
    d = db()
    for k in ("tg_channel", "tg_support"):
        v = request.form.get(k, "").strip()
        if v and not (v.startswith("https://t.me/") or v.startswith("https://telegram.me/")):
            flash("Telegram link must start with https://t.me/")
            return redirect(url_for("admin"))
        d.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, v))
    flash("Links saved")
    return redirect(url_for("admin"))


# ---------- KHQR Pay (ABA + Bakong) ----------
RAILS = ("bakong", "aba")


def get_setting(k, default=""):
    r = db().execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()
    if r and r["value"]:
        return r["value"]
    return os.environ.get(k.upper(), default)  # env is only a fallback


def rail_key(rail):
    """One key may serve both rails; a per-rail key overrides it."""
    return get_setting(f"khqrpay_key_{rail}") or get_setting("khqrpay_key")


def khqr_call(rail, method, path, payload=None):
    key = rail_key(rail)
    if not key:
        return {"ok": False, "error_text": f"{rail.upper()} payment is not configured"}
    base = get_setting("khqrpay_base", "https://khqrpay.site").rstrip("/")
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers={
        "Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except Exception:
            return {"ok": False, "error_text": f"HTTP {e.code}"}
    except Exception as e:
        return {"ok": False, "error_text": f"Payment service unreachable ({type(e).__name__})"}


@app.route("/topup", methods=["GET", "POST"])
@login_required
def topup():
    avail = avail_rails()
    if request.method == "POST":
        rail = request.form.get("rail", "")
        try:
            amount = round(float(request.form.get("amount", 0)), 2)
        except ValueError:
            amount = 0
        if rail not in avail or not (0.01 <= amount <= 500):
            flash(tr("err_topup"))
            return redirect(url_for("topup"))
        res = khqr_call(rail, "POST", f"/api/v1/{rail}/create", {"amount": amount})
        if not res.get("ok"):
            flash(res.get("error_text") or res.get("msg") or tr("err_qr"))
            return redirect(url_for("topup"))
        tid = db().execute(
            "INSERT INTO topups(user_id,rail,amount,payment_id,qr_image,checkout_url,expires_at,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (g.user["id"], rail, amount, str(res["id"]), res.get("qr_image"),
             res.get("checkout_url"), res.get("expires_at"), int(time.time()))).lastrowid
        return redirect(url_for("topup_pay", tid=tid))
    recent = db().execute("SELECT * FROM topups WHERE user_id=? ORDER BY id DESC LIMIT 10",
                          (g.user["id"],)).fetchall()
    return render_template("topup.html", avail=avail, recent=recent)


def own_topup(tid):
    t = db().execute("SELECT * FROM topups WHERE id=? AND user_id=?",
                     (tid, g.user["id"])).fetchone()
    if not t:
        abort(404)
    return t


@app.route("/topup/<int:tid>")
@login_required
def topup_pay(tid):
    return render_template("topup_pay.html", t=own_topup(tid))


@app.route("/topup/<int:tid>/status")
@login_required
def topup_status(tid):
    t = own_topup(tid)
    if t["status"] != "Pending":
        return {"status": t["status"]}
    res = khqr_call(t["rail"], "GET", f"/api/v1/payment?id={t['payment_id']}")
    p = res.get("payment") or {}
    status = p.get("status")
    if not res.get("ok") or not status:
        return {"status": "Pending"}
    d = db()
    if status == "Paid":
        try:
            ok_amount = abs(float(p.get("amount")) - t["amount"]) < 0.001
        except (TypeError, ValueError):
            ok_amount = False
        if not ok_amount:
            status = "UnderPaid"  # never auto-credit a mismatch
        else:
            d.execute("BEGIN IMMEDIATE")
            changed = d.execute("UPDATE topups SET status='Paid' WHERE id=? AND status='Pending'",
                                (tid,)).rowcount  # credit exactly once
            if changed:
                d.execute("UPDATE users SET balance=balance+? WHERE id=?", (t["amount"], t["user_id"]))
                d.execute("INSERT INTO transactions(user_id,amount,type,ref,created_at) VALUES(?,?,?,?,?)",
                          (t["user_id"], t["amount"], "topup", f"khqr:{t['payment_id']}", int(time.time())))
            d.execute("COMMIT")
            return {"status": "Paid"}
    if status in ("Expired", "Failed", "UnderPaid"):
        d.execute("UPDATE topups SET status=? WHERE id=? AND status='Pending'", (status, tid))
    return {"status": status}


@app.route("/admin/settings", methods=["POST"])
@admin_required
def admin_settings():
    d = db()
    for k in ("khqrpay_key", "khqrpay_key_bakong", "khqrpay_key_aba"):
        v = request.form.get(k, "").strip()
        if v:  # empty = keep current
            d.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, v))
        if request.form.get("clear_" + k):
            d.execute("DELETE FROM settings WHERE key=?", (k,))
    rails = [r for r in RAILS if request.form.get("rail_" + r)]
    d.execute("INSERT OR REPLACE INTO settings VALUES('khqrpay_rails',?)", (",".join(rails) or "none",))
    flash("Payment settings saved")
    return redirect(url_for("admin"))


@app.route("/admin/health", methods=["POST"])
@admin_required
def admin_health():
    base = get_setting("khqrpay_base", "https://khqrpay.site").rstrip("/")
    try:
        with urllib.request.urlopen(base + "/health", timeout=10) as r:
            flash(f"KHQR Pay /health: HTTP {r.status} OK")
    except Exception as e:
        flash(f"KHQR Pay /health failed: {type(e).__name__}")
    return redirect(url_for("admin"))


def avail_rails():
    enabled = get_setting("khqrpay_rails")
    allowed = enabled.split(",") if enabled else list(RAILS)
    return [r for r in RAILS if r in allowed and rail_key(r)]


def max_qty(user):
    return 500 if user["role"] == "reseller" else 5


def release_checkout(cid, status):
    """Free the reserved keys and close the checkout."""
    d = db()
    d.execute("BEGIN IMMEDIATE")
    d.execute("UPDATE keys SET status='available', checkout_id=NULL "
              "WHERE checkout_id=? AND status='reserved'", (cid,))
    d.execute("UPDATE checkouts SET status=? WHERE id=? AND status='Pending'", (status, cid))
    d.execute("COMMIT")


def release_stale():
    old = db().execute("SELECT id FROM checkouts WHERE status='Pending' AND created_at<?",
                       (int(time.time()) - 720,)).fetchall()  # QR lives 10 min
    for r in old:
        release_checkout(r["id"], "Expired")


@app.route("/pay/<int:mod_id>", methods=["POST"])
@login_required
def pay_now(mod_id):
    """Instant payment: reserve keys, show KHQR, deliver keys when Paid."""
    rail = request.form.get("rail", "")
    try:
        qty = int(request.form.get("qty", 1))
    except ValueError:
        qty = 0
    if rail not in avail_rails() or qty < 1 or qty > max_qty(g.user):
        flash(tr("err_pay"))
        return redirect(url_for("shop"))
    release_stale()
    d = db()
    d.execute("BEGIN IMMEDIATE")
    try:
        mod = d.execute("SELECT * FROM mods WHERE id=? AND active=1", (mod_id,)).fetchone()
        if not mod:
            raise ValueError(tr("err_nomod"))
        total = round(unit_price(g.user, mod) * qty, 2)
        if not (0.01 <= total <= 10000):
            raise ValueError(tr("err_range"))
        keys = d.execute("SELECT id FROM keys WHERE mod_id=? AND status='available' ORDER BY id LIMIT ?",
                         (mod_id, qty)).fetchall()
        if len(keys) < qty:
            raise ValueError(tr("err_stock"))
        cid = d.execute("INSERT INTO checkouts(user_id,mod_id,qty,total,rail,created_at)"
                        " VALUES(?,?,?,?,?,?)",
                        (g.user["id"], mod_id, qty, total, rail, int(time.time()))).lastrowid
        d.executemany("UPDATE keys SET status='reserved', checkout_id=? WHERE id=?",
                      [(cid, k["id"]) for k in keys])
        d.execute("COMMIT")
    except ValueError as e:
        d.execute("ROLLBACK")
        flash(str(e))
        return redirect(url_for("shop"))
    except Exception:
        d.execute("ROLLBACK")
        raise
    res = khqr_call(rail, "POST", f"/api/v1/{rail}/create", {"amount": total})
    if not res.get("ok"):
        release_checkout(cid, "Failed")
        flash(res.get("error_text") or res.get("msg") or tr("err_qr"))
        return redirect(url_for("shop"))
    d.execute("UPDATE checkouts SET payment_id=?, qr_image=?, checkout_url=?, expires_at=? WHERE id=?",
              (str(res["id"]), res.get("qr_image"), res.get("checkout_url"),
               res.get("expires_at"), cid))
    return redirect(url_for("checkout_page", cid=cid))


def own_checkout(cid):
    c = db().execute("""SELECT c.*, m.name, m.duration_days, m.duration_unit, (SELECT name FROM games WHERE id=m.game_id) AS game_name FROM checkouts c JOIN mods m ON m.id=c.mod_id
                        WHERE c.id=? AND c.user_id=?""", (cid, g.user["id"])).fetchone()
    if not c:
        abort(404)
    return c


@app.route("/checkout/<int:cid>")
@login_required
def checkout_page(cid):
    return render_template("checkout.html", c=own_checkout(cid))


@app.route("/checkout/<int:cid>/status")
@login_required
def checkout_status(cid):
    c = own_checkout(cid)
    if c["status"] != "Pending":
        return {"status": c["status"], "order_id": c["order_id"]}
    res = khqr_call(c["rail"], "GET", f"/api/v1/payment?id={c['payment_id']}")
    p = res.get("payment") or {}
    status = p.get("status")
    if not res.get("ok") or not status:
        return {"status": "Pending"}
    d = db()
    if status == "Paid":
        try:
            ok_amount = abs(float(p.get("amount")) - c["total"]) < 0.001
        except (TypeError, ValueError):
            ok_amount = False
        if ok_amount:
            d.execute("BEGIN IMMEDIATE")
            changed = d.execute("UPDATE checkouts SET status='Paid' WHERE id=? AND status='Pending'",
                                (cid,)).rowcount  # deliver exactly once
            if changed:
                u = d.execute("SELECT role FROM users WHERE id=?", (c["user_id"],)).fetchone()
                oid = d.execute("INSERT INTO orders(user_id,mod_id,qty,total,buyer_role,created_at)"
                                " VALUES(?,?,?,?,?,?)",
                                (c["user_id"], c["mod_id"], c["qty"], c["total"], u["role"],
                                 int(time.time()))).lastrowid
                d.execute("UPDATE keys SET status='sold', order_id=? WHERE checkout_id=?", (oid, cid))
                d.execute("UPDATE checkouts SET order_id=? WHERE id=?", (oid, cid))
                d.execute("INSERT INTO transactions(user_id,amount,type,ref,created_at) VALUES(?,?,?,?,?)",
                          (c["user_id"], 0, "direct_pay", f"order:{oid} khqr:{c['payment_id']}",
                           int(time.time())))
            d.execute("COMMIT")
            row = d.execute("SELECT order_id FROM checkouts WHERE id=?", (cid,)).fetchone()
            return {"status": "Paid", "order_id": row["order_id"]}
        status = "UnderPaid"  # mismatch: never auto-deliver
    if status in ("Expired", "Failed", "UnderPaid"):
        release_checkout(cid, status)
    return {"status": status}


# ---------- validity (hours / days / months) ----------
UNITS = {"hour": ("Hour", 1, 8760), "day": ("Day", 24, 3650), "month": ("Month", 720, 120)}


def dur_unit(m):
    u = m["duration_unit"] if "duration_unit" in m.keys() else None
    return u if u in UNITS else "day"


def dur_label(m):
    if not m["duration_days"]:
        return m["name"]
    return f"{m['duration_days']} {tr('unit_' + UNITS[dur_unit(m)][0])}"


def dur_sort(m):
    return m["duration_days"] * UNITS[dur_unit(m)][1] if m["duration_days"] else 10 ** 9


def parse_duration(form):
    """(value, unit) from the admin form; value None = no fixed validity. Aborts on bad input."""
    unit = form.get("duration_unit", "day")
    if unit not in UNITS:
        abort(400)
    raw = form.get("duration_days", "").strip()
    try:
        val = int(raw) if raw else None
    except ValueError:
        abort(400)
    if val is not None and not 1 <= val <= UNITS[unit][2]:
        abort(400)
    return val, unit


# ---------- pricing ----------
def unit_price(user, mod):
    if user and user["role"] == "reseller":
        r = db().execute("SELECT price FROM reseller_prices WHERE user_id=? AND mod_id=?",
                         (user["id"], mod["id"])).fetchone()
        if r:
            return r["price"]
        return round(mod["price"] * (1 - user["discount_pct"] / 100), 2)
    return mod["price"]


# ---------- shop ----------
@app.route("/")
def shop():
    mods = db().execute("""SELECT m.*, (SELECT COUNT(*) FROM keys k
        WHERE k.mod_id=m.id AND k.status='available') AS stock
        FROM mods m WHERE m.active=1 ORDER BY m.id DESC""").fetchall()
    release_stale()
    games = {gm["id"]: gm for gm in db().execute("SELECT * FROM games WHERE active=1")}
    groups = {}
    for m in mods:
        gid = m["game_id"] or 0
        if gid and gid not in games:
            continue  # its game is hidden
        groups.setdefault(gid, []).append(m)
    data = []
    for gid in sorted(groups):
        gm = games.get(gid)
        items = []
        for m in sorted(groups[gid], key=lambda x: (dur_sort(x), x["id"])):
            items.append({"id": m["id"], "stock": m["stock"], "price": unit_price(g.user, m),
                          "label": dur_label(m)})
        data.append({"id": gid, "name": gm["name"] if gm else "Other",
                     "image": gm["image"] if gm else None, "setup": (gm["setup"] or "") if gm else "",
                     "items": items, "stock": sum(i["stock"] for i in items),
                     "min_price": min(i["price"] for i in items)})
    me_info = {"logged": bool(g.user), "balance": float(g.user["balance"]) if g.user else 0.0,
               "maxqty": max_qty(g.user) if g.user else 0}
    return render_template("shop.html", data=data, me_info=me_info, rails=avail_rails(),
                           promos=promos_list())


@app.route("/buy/<int:mod_id>", methods=["POST"])
@login_required
def buy(mod_id):
    try:
        qty = int(request.form.get("qty", 1))
    except ValueError:
        qty = 0
    if g.user["role"] != "reseller":
        qty = min(qty, 5)
    if qty < 1 or qty > 500:
        flash(tr("err_qty"))
        return redirect(url_for("shop"))
    d = db()
    d.execute("BEGIN IMMEDIATE")  # lock: no double-selling, no negative balance
    try:
        mod = d.execute("SELECT * FROM mods WHERE id=? AND active=1", (mod_id,)).fetchone()
        user = d.execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
        if not mod:
            raise ValueError(tr("err_nomod"))
        total = round(unit_price(user, mod) * qty, 2)
        if user["balance"] < total:
            raise ValueError(tr("err_balance", n=f"{total:.2f}"))
        keys = d.execute("SELECT id FROM keys WHERE mod_id=? AND status='available' ORDER BY id LIMIT ?",
                         (mod_id, qty)).fetchall()
        if len(keys) < qty:
            raise ValueError(tr("err_stock"))
        now = int(time.time())
        oid = d.execute("INSERT INTO orders(user_id,mod_id,qty,total,buyer_role,created_at)"
                        " VALUES(?,?,?,?,?,?)",
                        (user["id"], mod_id, qty, total, user["role"], now)).lastrowid
        d.executemany("UPDATE keys SET status='sold', order_id=? WHERE id=?",
                      [(oid, k["id"]) for k in keys])
        d.execute("UPDATE users SET balance=balance-? WHERE id=?", (total, user["id"]))
        d.execute("INSERT INTO transactions(user_id,amount,type,ref,created_at) VALUES(?,?,?,?,?)",
                  (user["id"], -total, "purchase", f"order:{oid}", now))
        d.execute("COMMIT")
    except ValueError as e:
        d.execute("ROLLBACK")
        flash(str(e))
        return redirect(url_for("shop"))
    except Exception:
        d.execute("ROLLBACK")
        raise
    return redirect(url_for("order_view", oid=oid))


# ---------- after-purchase guide (video / description / links / file) ----------
GUIDE_EXT = {".zip", ".rar", ".7z", ".apk", ".pdf", ".txt", ".ipa"}


def save_guide_file(f):
    """Downloadable file for buyers: whitelisted extension, max 30 MB. Returns (stored, shown_name)."""
    if not f or not f.filename:
        return None, None
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in GUIDE_EXT:
        raise ValueError("File type not allowed (zip, rar, 7z, apk, pdf, txt, ipa)")
    f.stream.seek(0, os.SEEK_END)
    if f.stream.tell() > 30 * 1024 * 1024:
        raise ValueError("File must be 30 MB or smaller")
    f.stream.seek(0)
    os.makedirs(GUIDE_DIR, exist_ok=True)
    name = secrets.token_hex(10) + ext
    f.save(os.path.join(GUIDE_DIR, name))
    shown = re.sub(r"[^\w.\- ]", "_", os.path.basename(f.filename))[:80] or ("file" + ext)
    return name, shown


def rm_guide_file(name):
    if name and not name.startswith("https://"):
        try:
            os.remove(os.path.join(GUIDE_DIR, os.path.basename(name)))
        except OSError:
            pass


def embed_url(u):
    m = re.match(r"https://(?:www\.|m\.)?(?:youtube\.com/(?:watch\?(?:.*&)?v=|shorts/)|youtu\.be/)([\w-]{11})", u)
    return f"https://www.youtube.com/embed/{m.group(1)}" if m else None


def build_guide(gid):
    """What a buyer sees after purchase for this game, or None when nothing is set."""
    if not gid:
        return None
    r = db().execute("SELECT * FROM guides WHERE game_id=?", (gid,)).fetchone()
    if not r:
        return None
    links = [x.strip() for x in (r["links"] or "").splitlines()
             if x.strip().startswith(("https://", "http://"))]
    video = None
    if r["video"]:
        if r["video"].startswith("https://"):
            e = embed_url(r["video"])
            video = {"kind": "embed", "src": e} if e else {"kind": "link", "src": r["video"]}
        else:
            video = {"kind": "file", "src": f"/guide/{gid}/video"}
    out = {"text": (r["text"] or "").strip(), "links": links, "video": video,
           "file": ({"name": r["file_name"] or "Download", "src": f"/guide/{gid}/file"} if r["file"] else None)}
    return out if (out["text"] or links or video or out["file"]) else None


def can_open_guide(gid):
    if g.user["role"] == "admin":
        return True
    return bool(db().execute("""SELECT 1 FROM orders o JOIN mods m ON m.id=o.mod_id
        WHERE o.user_id=? AND m.game_id=? LIMIT 1""", (g.user["id"], gid)).fetchone())


@app.route("/guide/<int:gid>/<kind>")
@login_required
def guide_media(gid, kind):
    if kind not in ("video", "file") or not can_open_guide(gid):
        abort(404)
    r = db().execute("SELECT * FROM guides WHERE game_id=?", (gid,)).fetchone()
    name = r[kind] if r else None
    if not name or name.startswith("https://"):
        abort(404)
    resp = send_from_directory(GUIDE_DIR, name, as_attachment=(kind == "file"),
                               download_name=(r["file_name"] if kind == "file" else None))
    resp.headers["Cache-Control"] = "private, max-age=3600"
    return resp


@app.route("/admin/guide/<int:gid>", methods=["POST"])
@admin_required
def admin_guide(gid):
    d = db()
    if not d.execute("SELECT 1 FROM games WHERE id=?", (gid,)).fetchone():
        abort(404)
    old = d.execute("SELECT * FROM guides WHERE game_id=?", (gid,)).fetchone()
    video = old["video"] if old else None
    file_, fname = (old["file"], old["file_name"]) if old else (None, None)
    try:
        up = save_video(request.files.get("video_file"), GUIDE_DIR)
        url = request.form.get("video_url", "").strip()
        if url and not url.startswith("https://"):
            raise ValueError("Video link must start with https://")
        nf, nn = save_guide_file(request.files.get("file"))
    except ValueError as e:
        flash(str(e))
        return redirect(url_for("admin"))
    if request.form.get("rm_video") or up or url:
        rm_guide_file(video)
        video = None
    if up or url:
        video = up or url
    if request.form.get("rm_file") or nf:
        rm_guide_file(file_)
        file_, fname = None, None
    if nf:
        file_, fname = nf, nn
    d.execute("INSERT OR REPLACE INTO guides(game_id,text,links,video,file,file_name) VALUES(?,?,?,?,?,?)",
              (gid, request.form.get("text", "").strip()[:4000],
               request.form.get("links", "").strip()[:2000], video, file_, fname))
    flash("After-purchase guide saved")
    return redirect(url_for("admin"))


def order_keys(oid):
    return [r["key_value"] for r in
            db().execute("SELECT key_value FROM keys WHERE order_id=?", (oid,))]


@app.route("/order/<int:oid>")
@login_required
def order_view(oid):
    o = db().execute("""SELECT o.*, m.name, m.game_id, m.duration_days, m.duration_unit, (SELECT name FROM games WHERE id=m.game_id) AS game_name FROM orders o JOIN mods m ON m.id=o.mod_id
                        WHERE o.id=? AND o.user_id=?""", (oid, g.user["id"])).fetchone()
    if not o:
        abort(404)
    return render_template("order.html", o=o, keys=order_keys(oid), guide=build_guide(o["game_id"]))


@app.route("/account")
@login_required
def account():
    d = db()
    tx = d.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 50",
                   (g.user["id"],)).fetchall()
    tops = d.execute("SELECT * FROM topups WHERE user_id=? ORDER BY id DESC LIMIT 20",
                     (g.user["id"],)).fetchall()
    stats = d.execute("SELECT COUNT(*) n, COALESCE(SUM(total),0) s FROM orders WHERE user_id=?",
                      (g.user["id"],)).fetchone()
    return render_template("account.html", tx=tx, tops=tops, stats=stats,
                           fmt=lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t or 0)))


@app.route("/orders")
@login_required
def orders():
    rows = db().execute("""SELECT o.*, m.name, m.duration_days, m.duration_unit, (SELECT name FROM games WHERE id=m.game_id) AS game_name FROM orders o JOIN mods m ON m.id=o.mod_id
                           WHERE o.user_id=? ORDER BY o.id DESC""", (g.user["id"],)).fetchall()
    return render_template("orders.html", orders=rows)


@app.route("/orders.csv")
@login_required
def orders_csv():
    rows = db().execute("""SELECT o.id, m.name, o.qty, o.total, o.created_at
        FROM orders o JOIN mods m ON m.id=o.mod_id WHERE o.user_id=? ORDER BY o.id""",
                        (g.user["id"],)).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["order_id", "mod", "qty", "total", "time", "keys"])
    for r in rows:
        w.writerow([r["id"], r["name"], r["qty"], r["total"],
                    time.strftime("%Y-%m-%d %H:%M", time.localtime(r["created_at"])),
                    " ".join(order_keys(r["id"]))])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=orders.csv"})


# ---------- admin ----------
@app.route("/admin")
@admin_required
def admin():
    mods = db().execute("""SELECT m.*,
        (SELECT COUNT(*) FROM keys k WHERE k.mod_id=m.id AND k.status='available') AS stock,
        (SELECT COUNT(*) FROM keys k WHERE k.mod_id=m.id AND k.status='sold') AS sold
        FROM mods m ORDER BY m.id DESC""").fetchall()
    users = db().execute("SELECT * FROM users ORDER BY role, id DESC").fetchall()
    games = db().execute("SELECT * FROM games ORDER BY id DESC").fetchall()
    cfg = {"general": bool(get_setting("khqrpay_key")),
           "bakong": bool(get_setting("khqrpay_key_bakong")),
           "aba": bool(get_setting("khqrpay_key_aba")),
           "on": avail_rails()}
    guides = {r["game_id"]: r for r in db().execute("SELECT * FROM guides")}
    return render_template("admin.html", mods=mods, users=users, cfg=cfg, games=games, guides=guides,
                           promos=promos_list())


@app.route("/admin/mod", methods=["POST"])
@admin_required
def admin_mod():
    try:
        price = float(request.form["price"])
    except (KeyError, ValueError):
        abort(400)
    if price < 0:
        abort(400)
    game_id = request.form.get("game_id", type=int)
    days, unit = parse_duration(request.form)
    name = request.form.get("name", "").strip()
    if not name:  # default: "<Game> <N> Hour/Day/Month"
        gm = db().execute("SELECT name FROM games WHERE id=?", (game_id,)).fetchone() if game_id else None
        name = " ".join(x for x in ((gm["name"] if gm else ""),
                                    (f"{days} {UNITS[unit][0]}" if days else "")) if x)
    if not name:
        abort(400)
    db().execute("INSERT INTO mods(name,description,price,game_id,duration_days,duration_unit) VALUES(?,?,?,?,?,?)",
                 (name, request.form.get("description", "").strip(), price, game_id, days, unit))
    flash("Item added")
    return redirect(url_for("admin"))


@app.route("/admin/mod/<int:mod_id>/edit", methods=["POST"])
@admin_required
def admin_mod_edit(mod_id):
    """Admin changes a service's validity (days), price and name at any time."""
    d = db()
    m = d.execute("SELECT * FROM mods WHERE id=?", (mod_id,)).fetchone()
    if not m:
        abort(404)
    days, unit = parse_duration(request.form)
    try:
        price = float(request.form["price"])
    except (KeyError, ValueError):
        abort(400)
    if price < 0:
        abort(400)
    name = request.form.get("name", "").strip() or m["name"]
    d.execute("UPDATE mods SET duration_days=?, duration_unit=?, price=?, name=? WHERE id=?",
              (days, unit, price, name, mod_id))
    flash("Item updated")
    return redirect(url_for("admin"))


@app.route("/admin/mod/<int:mod_id>/game", methods=["POST"])
@admin_required
def admin_mod_game(mod_id):
    db().execute("UPDATE mods SET game_id=? WHERE id=?",
                 (request.form.get("game_id", type=int), mod_id))
    return redirect(url_for("admin"))


def save_image(f):
    """Validate by magic bytes (not the client's filename) and store under a random name."""
    if not f or not f.filename:
        return None
    head = f.stream.read(16)
    f.stream.seek(0)
    if head.startswith(b"\x89PNG"):
        ext = ".png"
    elif head[:3] == b"\xff\xd8\xff":
        ext = ".jpg"
    elif head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        ext = ".webp"
    else:
        raise ValueError("Image must be PNG, JPG or WEBP")
    f.stream.seek(0, os.SEEK_END)
    if f.stream.tell() > 3 * 1024 * 1024:
        raise ValueError("Image must be 3 MB or smaller")
    f.stream.seek(0)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    name = secrets.token_hex(10) + ext
    f.save(os.path.join(UPLOAD_DIR, name))
    return name


def remove_image(name):
    if name:
        try:
            os.remove(os.path.join(UPLOAD_DIR, os.path.basename(name)))
        except OSError:
            pass


def save_video(f, folder=None):
    """Promo video: mp4 or webm, max 30 MB, validated by magic bytes."""
    if not f or not f.filename:
        return None
    head = f.stream.read(16)
    f.stream.seek(0, os.SEEK_END)
    size = f.stream.tell()
    f.stream.seek(0)
    if head[4:8] == b"ftyp":
        ext = ".mp4"
    elif head[:4] == b"\x1a\x45\xdf\xa3":
        ext = ".webm"
    else:
        raise ValueError("Video must be MP4 or WEBM")
    if size > 30 * 1024 * 1024:
        raise ValueError("Video must be 30 MB or smaller")
    folder = folder or UPLOAD_DIR
    os.makedirs(folder, exist_ok=True)
    name = secrets.token_hex(10) + ext
    f.save(os.path.join(folder, name))
    return name


SLOTS = {"brand": "brand_video", "1": "promo1", "2": "promo2", "3": "promo3"}


def video_src(v):
    return (v if v.startswith("https://") else "/img/" + v) if v else ""


def promos_list():
    out = []
    for n in (1, 2, 3):
        v = get_setting(f"promo{n}")
        if v:
            out.append({"n": n, "raw": v, "src": video_src(v)})
    return out


@app.route("/admin/promo", methods=["POST"])
@admin_required
def admin_promo():
    d = db()
    name = request.form.get("site_name", "").strip()[:40]
    d.execute("INSERT OR REPLACE INTO settings VALUES('site_name',?)", (name,))
    d.execute("INSERT OR REPLACE INTO settings VALUES('brand_key',?)", ("1" if request.form.get("brand_key") else "0",))
    for slot, key in SLOTS.items():
        old = get_setting(key)
        new = None
        try:
            up = save_video(request.files.get(f"video_{slot}"))
        except ValueError as e:
            flash(f"Video {slot}: {e}")
            continue
        url = request.form.get(f"url_{slot}", "").strip()
        if up:
            new = up
        elif url:
            if not url.startswith("https://"):
                flash(f"Video {slot}: link must start with https://")
                continue
            new = url
        if new is not None:
            d.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (key, new))
            if old and not old.startswith("https://") and old != new:
                remove_image(old)
    flash("Header / promo videos saved")
    return redirect(url_for("admin"))


@app.route("/admin/video/<slot>/delete", methods=["POST"])
@admin_required
def admin_video_delete(slot):
    key = SLOTS.get(slot)
    if not key:
        abort(404)
    old = get_setting(key)
    db().execute("DELETE FROM settings WHERE key=?", (key,))
    if old and not old.startswith("https://"):
        remove_image(old)
    flash("Video deleted")
    return redirect(url_for("admin"))


@app.route("/img/<path:name>")
def image(name):
    if ".." in name:
        abort(404)
    resp = send_from_directory(UPLOAD_DIR, name)
    resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp


@app.route("/admin/game", methods=["POST"])
@admin_required
def admin_game():
    name = request.form.get("name", "").strip()
    if not name:
        abort(400)
    try:
        img = save_image(request.files.get("image"))
    except ValueError as e:
        flash(str(e))
        return redirect(url_for("admin"))
    db().execute("INSERT INTO games(name,image,setup) VALUES(?,?,?)",
                 (name, img, request.form.get("setup", "").strip()[:500]))
    flash("Game added")
    return redirect(url_for("admin"))


@app.route("/admin/game/<int:gid>", methods=["POST"])
@admin_required
def admin_game_edit(gid):
    gm = db().execute("SELECT * FROM games WHERE id=?", (gid,)).fetchone()
    if not gm:
        abort(404)
    name = request.form.get("name", "").strip() or gm["name"]
    try:
        img = save_image(request.files.get("image"))
    except ValueError as e:
        flash(str(e))
        return redirect(url_for("admin"))
    if img:
        remove_image(gm["image"])
    db().execute("UPDATE games SET name=?, image=?, setup=? WHERE id=?",
                 (name, img or gm["image"], request.form.get("setup", "").strip()[:500], gid))
    flash("Game updated")
    return redirect(url_for("admin"))


@app.route("/admin/game/<int:gid>/toggle", methods=["POST"])
@admin_required
def admin_game_toggle(gid):
    db().execute("UPDATE games SET active=1-active WHERE id=?", (gid,))
    return redirect(url_for("admin"))


@app.route("/admin/mod/<int:mod_id>/toggle", methods=["POST"])
@admin_required
def admin_mod_toggle(mod_id):
    db().execute("UPDATE mods SET active=1-active WHERE id=?", (mod_id,))
    return redirect(url_for("admin"))


def mod_block_reason(d, mod_id):
    """Why a service cannot be deleted (None = safe). Sold history must stay intact."""
    if d.execute("SELECT 1 FROM orders WHERE mod_id=? LIMIT 1", (mod_id,)).fetchone():
        return "it already has orders (use Show/Hide instead)"
    if d.execute("SELECT 1 FROM checkouts WHERE mod_id=? AND status='Pending' LIMIT 1", (mod_id,)).fetchone():
        return "a customer payment is pending (try again in 10 minutes)"
    return None


def delete_mod_rows(d, mod_id):
    d.execute("DELETE FROM keys WHERE mod_id=?", (mod_id,))
    d.execute("DELETE FROM reseller_prices WHERE mod_id=?", (mod_id,))
    d.execute("DELETE FROM checkouts WHERE mod_id=?", (mod_id,))
    d.execute("DELETE FROM mods WHERE id=?", (mod_id,))


@app.route("/admin/mod/<int:mod_id>/delete", methods=["POST"])
@admin_required
def admin_mod_delete(mod_id):
    d = db()
    m = d.execute("SELECT * FROM mods WHERE id=?", (mod_id,)).fetchone()
    if not m:
        abort(404)
    why = mod_block_reason(d, mod_id)
    if why:
        flash(f"Cannot delete \"{m['name']}\": {why}")
        return redirect(url_for("admin"))
    d.execute("BEGIN IMMEDIATE")
    try:
        delete_mod_rows(d, mod_id)
        d.execute("COMMIT")
    except Exception:
        d.execute("ROLLBACK")
        raise
    flash(f"Deleted service \"{m['name']}\"")
    return redirect(url_for("admin"))


@app.route("/admin/game/<int:gid>/delete", methods=["POST"])
@admin_required
def admin_game_delete(gid):
    d = db()
    gm = d.execute("SELECT * FROM games WHERE id=?", (gid,)).fetchone()
    if not gm:
        abort(404)
    mods = d.execute("SELECT * FROM mods WHERE game_id=?", (gid,)).fetchall()
    for m in mods:
        why = mod_block_reason(d, m["id"])
        if why:
            flash(f"Cannot delete game \"{gm['name']}\": service \"{m['name']}\" — {why}")
            return redirect(url_for("admin"))
    d.execute("BEGIN IMMEDIATE")
    try:
        for m in mods:
            delete_mod_rows(d, m["id"])
        gd = d.execute("SELECT * FROM guides WHERE game_id=?", (gid,)).fetchone()
        d.execute("DELETE FROM guides WHERE game_id=?", (gid,))
        d.execute("DELETE FROM games WHERE id=?", (gid,))
        d.execute("COMMIT")
    except Exception:
        d.execute("ROLLBACK")
        raise
    remove_image(gm["image"])
    if gd:
        rm_guide_file(gd["video"])
        rm_guide_file(gd["file"])
    flash(f"Deleted game \"{gm['name']}\" and {len(mods)} service(s)")
    return redirect(url_for("admin"))


@app.route("/admin/keys/<int:mod_id>", methods=["POST"])
@admin_required
def admin_keys(mod_id):
    # 1 line = 1 key. Order is kept (first line is sold first); blank lines and repeats inside the paste are dropped.
    raw = request.form.get("keys", "").replace("\u200b", "").replace("\ufeff", "")
    lines = list(dict.fromkeys(l.strip()[:500] for l in raw.splitlines() if l.strip()))
    if not lines:
        flash("Paste at least one key (one key per line)")
        return redirect(url_for("admin"))
    if not db().execute("SELECT 1 FROM mods WHERE id=?", (mod_id,)).fetchone():
        abort(404)
    d = db()
    before = d.execute("SELECT COUNT(*) c FROM keys WHERE mod_id=?", (mod_id,)).fetchone()["c"]
    d.execute("BEGIN")
    d.executemany("INSERT OR IGNORE INTO keys(mod_id,key_value) VALUES(?,?)",
                  [(mod_id, k) for k in lines])
    d.execute("COMMIT")
    after = d.execute("SELECT COUNT(*) c FROM keys WHERE mod_id=?", (mod_id,)).fetchone()["c"]
    added = after - before
    flash(f"Added {added} key(s) from {len(lines)} line(s)"
          + (f" — {len(lines) - added} already in stock, skipped" if len(lines) > added else ""))
    return redirect(url_for("admin"))


@app.route("/admin/user/<int:uid>", methods=["POST"])
@admin_required
def admin_user(uid):
    f = request.form
    role = f.get("role", "user")
    if role not in ("user", "reseller", "admin"):
        abort(400)
    d = db()
    d.execute("BEGIN")
    d.execute("UPDATE users SET role=?, discount_pct=?, active=? WHERE id=?",
              (role, float(f.get("discount_pct") or 0), 1 if f.get("active") else 0, uid))
    topup = float(f.get("topup") or 0)
    if topup:
        d.execute("UPDATE users SET balance=balance+? WHERE id=?", (topup, uid))
        d.execute("INSERT INTO transactions(user_id,amount,type,ref,created_at) VALUES(?,?,?,?,?)",
                  (uid, topup, "topup", f"admin:{g.user['id']}", int(time.time())))
    d.execute("COMMIT")
    flash("User updated")
    return redirect(url_for("admin"))


@app.route("/admin/price", methods=["POST"])
@admin_required
def admin_price():
    f = request.form
    uid, mid = int(f["user_id"]), int(f["mod_id"])
    if f.get("price", "").strip() == "":
        db().execute("DELETE FROM reseller_prices WHERE user_id=? AND mod_id=?", (uid, mid))
    else:
        db().execute("INSERT OR REPLACE INTO reseller_prices VALUES(?,?,?)",
                     (uid, mid, float(f["price"])))
    flash("Reseller price saved")
    return redirect(url_for("admin"))


# ---------- templates ----------
BASE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ site_name }}</title>
<style>
:root{--bg:#0f1226;--card:#181c3a;--line:#2a2f5c;--txt:#eef0ff;--mut:#9aa0cc;--acc:#6c5ce7;--acc2:#00d2a8;--warn:#3a3210}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Noto Sans Khmer",sans-serif;background:linear-gradient(160deg,#0f1226,#1a1446);
color:var(--txt);max-width:900px;margin:0 auto;padding:14px;min-height:100vh}
a{color:var(--acc2);text-decoration:none}
nav{display:flex;gap:14px;flex-wrap:wrap;align-items:center;background:var(--card);border:1px solid var(--line);
border-radius:14px;padding:10px 14px;margin-bottom:12px}
nav b a{color:#fff;font-size:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;margin:10px 0}
.flash{background:var(--warn);border:1px solid #6b5a14;color:#ffe9a3;padding:10px;border-radius:10px;margin:8px 0}
input,select,textarea{background:#0f1230;color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:8px;margin:3px}
button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:9px 14px;margin:3px;font-weight:600;cursor:pointer}
button[formaction],button.alt{background:var(--acc2);color:#04241d}
form{display:flex;flex-wrap:wrap;align-items:center;gap:2px}
h3{margin:18px 0 6px}small{color:var(--mut)}
table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid var(--line);padding:6px;text-align:left;font-size:14px}
code{background:#0f1230;border:1px dashed var(--acc);padding:4px 8px;border-radius:6px;font-size:15px;word-break:break-all}
.price{color:var(--acc2);font-weight:700}
.game{display:flex;align-items:center;gap:12px;margin-top:18px}
.game img{width:88px;height:88px;object-fit:cover;border-radius:14px;border:1px solid var(--line)}
.game h3{margin:0;font-size:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin-top:10px}
.gcard{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:10px;display:flex;flex-direction:column;gap:6px}
.gcard img{width:100%;aspect-ratio:1;object-fit:cover;border-radius:10px}
.gcard button{width:100%;margin:0}
.ov{position:fixed;inset:0;background:rgba(0,0,0,.65);display:flex;align-items:flex-end;justify-content:center;z-index:50}
.ov[hidden],[hidden]{display:none!important}
.modal{background:#1b2238;border:1px solid #33406b;border-radius:22px;width:100%;max-width:480px;max-height:94vh;overflow:auto}
.modal form{display:block}.mh{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid #33406b;font-size:20px;font-weight:600}
.mb{padding:6px 20px}.modal label{display:block;color:var(--mut);margin:14px 0 6px}
.modal input[type=number]{width:100%;font-size:18px;padding:12px;border-radius:12px;margin:0}
.dd{position:relative}.dd>button,.opt{display:flex;align-items:center;gap:10px;width:100%;background:#0f1230;border:1px solid var(--line);
border-radius:12px;padding:10px;font-size:16px;text-align:left;margin:0;font-weight:500}
.dd>button .car{margin-left:auto}.dimg{width:36px;height:36px;border-radius:8px;object-fit:cover}
.ddl{position:absolute;left:0;right:0;top:100%;z-index:5;background:#0f1230;border:1px solid var(--line);border-radius:12px;max-height:240px;overflow:auto;margin-top:4px}
.chips{display:flex;gap:8px;flex-wrap:wrap}.chip{background:#232b47;color:#aab0d6;border:2px solid transparent;border-radius:12px;padding:12px 18px;margin:0}
.chip.on{border-color:#3b82f6;color:#fff;background:#172a4d}.chip:disabled{opacity:.35;cursor:not-allowed}
.mf{display:flex;justify-content:space-between;padding:16px 20px;border-top:1px solid #33406b;margin-top:10px}
.mf button{background:#0b7be0;padding:14px 24px;border-radius:14px;font-size:17px}button:disabled{opacity:.45;cursor:not-allowed}
button{transition:background .15s,color .15s,border-color .15s,transform .1s;-webkit-tap-highlight-color:transparent}
button:not(:disabled):active{transform:scale(.96);filter:brightness(1.25)}
.chip:not(:disabled):active{background:#2563eb;color:#fff;border-color:#60a5fa}
.chip.on{background:#2563eb;border-color:#93c5fd;color:#fff;box-shadow:0 0 0 3px rgba(59,130,246,.35)}
.opt:active,.dd>button:active{background:#1d2a52}
.mf button:not(:disabled):active{background:#0a5fb0}
button.alt:not(:disabled):active,button[formaction]:not(:disabled):active{background:#0fb88a}

#why{color:#ffd37a;font-size:14px;min-height:18px;margin:6px 0}
.menubtn{background:none;border:1px solid var(--line);color:#fff;font-size:22px;line-height:1;padding:6px 12px;margin:0;border-radius:10px}
.dov{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:90;opacity:0;pointer-events:none;transition:opacity .2s}
.drawer{position:fixed;top:0;left:0;bottom:0;width:280px;max-width:82vw;background:var(--card);border-right:1px solid var(--line);z-index:100;
transform:translateX(-100%);transition:transform .25s;display:flex;flex-direction:column;padding:16px;overflow:auto}
body.mopen .drawer{transform:none}body.mopen .dov{opacity:1;pointer-events:auto}
.drawer .who{border-bottom:1px solid var(--line);padding-bottom:12px;margin-bottom:8px}
.drawer .bal{font-size:26px;font-weight:700;color:var(--acc2);margin-top:4px}
.drawer a.mi{display:flex;align-items:center;gap:12px;color:var(--txt);padding:13px 10px;border-radius:10px;font-size:16px}
.drawer a.mi:hover{background:#232b47}.drawer .sp{margin-top:auto}.drawer svg.tg{width:22px;height:22px;flex:none}.drawer .hr{border-top:1px solid var(--line);margin:8px 0}
.lang{display:flex;gap:8px;align-items:center;padding:8px 10px}.lang a{border:1px solid var(--line);border-radius:10px;padding:6px 14px;color:var(--txt)}
.lang a.on{background:var(--acc);border-color:var(--acc);color:#fff}
nav.top{position:relative;min-height:54px}nav.top .brand{position:absolute;left:50%;transform:translateX(-50%);white-space:nowrap;margin:0}
nav.top .brand a{font-size:19px;font-weight:800;letter-spacing:.5px;background:linear-gradient(90deg,#fff,#00d2a8,#a29bfe,#fff);background-size:200% auto;
-webkit-background-clip:text;background-clip:text;color:transparent;animation:shine 4s linear infinite}
@keyframes shine{to{background-position:200% center}}
nav.top .brand a.bv{background:none;animation:none}nav.top.hasbv{min-height:58px;background:none;border:0;box-shadow:none;padding-top:0;padding-bottom:0}nav.top .brand video,nav.top .brand canvas{height:48px;max-width:50vw;display:block;object-fit:contain}
nav.top .brand video.k{position:absolute;width:2px;height:2px;opacity:0;pointer-events:none}
.gbtn{background:#d63031!important;color:#fff!important}.vprev{width:120px;height:68px;object-fit:cover;border-radius:8px;border:1px solid var(--line);vertical-align:middle;background:#000}
.promo{position:relative;border-radius:18px;overflow:hidden;border:1px solid var(--line);margin:8px 0;background:#000}
.ptrack{display:flex;overflow-x:auto;scroll-snap-type:x mandatory;scrollbar-width:none}.ptrack::-webkit-scrollbar{display:none}
.pslide{flex:0 0 100%;scroll-snap-align:center;aspect-ratio:16/9}.pslide video{width:100%;height:100%;object-fit:cover;display:block}
.pmute{position:absolute;right:10px;bottom:10px;width:40px;height:40px;border-radius:50%;background:rgba(0,0,0,.55);border:1px solid rgba(255,255,255,.3);font-size:18px;padding:0;margin:0}
.pdots{position:absolute;left:0;right:0;bottom:10px;display:flex;justify-content:center;gap:6px;pointer-events:none}
.pdots i{width:8px;height:8px;border-radius:50%;background:rgba(255,255,255,.4)}.pdots i.on{background:#fff}
.thumb{width:56px;height:56px;object-fit:cover;border-radius:10px;vertical-align:middle}
</style></head><body>
<nav class="top{{ ' hasbv' if brand_video }}">{% if me %}<button type="button" class="menubtn" id="menubtn" aria-label="Menu">&#9776;</button>{% endif %}
<b class="brand">{% if brand_video %}<a href="/" class="bv" title="{{ site_name }}"><video id="bvid" src="{{ brand_video }}" autoplay muted loop playsinline></video>{% if brand_key %}<canvas id="bcv"></canvas>{% endif %}</a>{% else %}<a href="/">{{ site_name }}</a>{% endif %}</b>
{% if not me %}<span style="margin-left:auto"><a href="/lang/kh">ខ្មែរ</a> | <a href="/lang/en">EN</a></span>{% endif %}</nav>
{% if me %}<div class="dov" id="dov"></div>
<aside class="drawer" id="drawer">
<div class="who"><b>{{ me.first_name }}</b> <small>({{ tv('role_', me.role) }})</small><br><small>{{ t('balance') }}</small>
<div class="bal">${{ '%.2f'|format(me.balance) }}</div></div>
<a class="mi" href="/">&#127968; {{ t('shop') }}</a>
<a class="mi" href="/topup">&#128176; {{ t('topup') }}</a>
<a class="mi" href="/account">&#128100; {{ t('account') }}</a>
<a class="mi" href="/orders">&#128230; {{ t('orders') }}</a>
<a class="mi" href="/account#history">&#129534; {{ t('history') }}</a>
{% if me.role=='admin' %}<a class="mi" href="/admin">&#9881; {{ t('admin') }}</a>{% endif %}
<div class="hr"></div>
{% if tg_channel %}<a class="mi" href="{{ tg_channel }}" target="_blank" rel="noopener"><svg class="tg" viewBox="0 0 240 240"><circle cx="120" cy="120" r="120" fill="#2AABEE"/><path fill="#fff" d="M54 118l121-47c6-2 11 1 9 9l-21 98c-1 7-6 9-12 5l-33-24-16 15c-2 2-3 3-6 3l2-34 61-55c3-2-1-4-4-2l-76 48-33-10c-7-2-7-7 2-10z"/></svg> {{ t('channel') }}</a>{% endif %}
{% if tg_support %}<a class="mi" href="{{ tg_support }}" target="_blank" rel="noopener"><svg class="tg" viewBox="0 0 240 240"><circle cx="120" cy="120" r="120" fill="#2AABEE"/><path fill="#fff" d="M54 118l121-47c6-2 11 1 9 9l-21 98c-1 7-6 9-12 5l-33-24-16 15c-2 2-3 3-6 3l2-34 61-55c3-2-1-4-4-2l-76 48-33-10c-7-2-7-7 2-10z"/></svg> {{ t('support') }}</a>{% endif %}
<div class="hr"></div>
<div class="lang">&#127760; {{ t('language') }}:
<a href="/lang/kh" class="{{ 'on' if lang=='kh' }}">ខ្មែរ</a><a href="/lang/en" class="{{ 'on' if lang=='en' }}">EN</a></div>
<a class="mi sp" href="/logout">&#128682; {{ t('logout') }}</a></aside>
<script>(function(){var b=document.body,m=document.getElementById('menubtn');
function t(o){b.classList.toggle('mopen',o)}
m.onclick=function(){t(!b.classList.contains('mopen'))};
document.getElementById('dov').onclick=function(){t(false)};
document.querySelectorAll('#drawer a').forEach(function(a){a.addEventListener('click',function(){t(false)})});
document.addEventListener('keydown',function(e){if(e.key==='Escape')t(false)});})();</script>{% endif %}
{% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}
{% if brand_video and brand_key %}<script>(function(){var v=document.getElementById('bvid'),c=document.getElementById('bcv');if(!v||!c)return;
var x=c.getContext('2d',{willReadFrequently:true}),W=0,H=0,on=false,last=0;
function size(){var r=(v.videoHeight||9)/(v.videoWidth||16);W=Math.min(v.videoWidth||480,480);H=Math.round(W*r);c.width=W;c.height=H}
function frame(ts){if(!on)return;requestAnimationFrame(frame);if(ts-last<40||v.readyState<2)return;last=ts;
if(!W)size();x.drawImage(v,0,0,W,H);var im;try{im=x.getImageData(0,0,W,H)}catch(e){fail();return}
var d=im.data,i,r,g,b,m,k;for(i=0;i<d.length;i+=4){r=d[i];g=d[i+1];b=d[i+2];m=r>b?r:b;k=g-m;
if(k>40){if(k>=90){d[i+3]=0}else{d[i+3]=(90-k)*5.1;d[i+1]=m}}}
x.putImageData(im,0,0)}
function fail(){on=false;c.style.display='none';v.classList.remove('k')}
v.classList.add('k');on=true;
v.addEventListener('loadedmetadata',size);
v.addEventListener('playing',function(){on=true;requestAnimationFrame(frame)});
v.addEventListener('error',fail);
document.addEventListener('visibilitychange',function(){if(!document.hidden){on=true;requestAnimationFrame(frame)}});
var p=v.play();if(p&&p.catch)p.catch(function(){});requestAnimationFrame(frame);})();</script>{% endif %}
{% block body %}{% endblock %}</body></html>"""

SHOP = """{% extends 'base.html' %}{% block body %}
{% if promos %}<div class="promo" id="promo"><div class="ptrack" id="ptrack">
{% for p in promos %}<div class="pslide"><video src="{{ p.src }}" muted playsinline preload="{{ 'auto' if loop.first else 'metadata' }}"{% if promos|length==1 %} loop{% endif %}></video></div>{% endfor %}</div>
<button type="button" class="pmute" id="pmute" aria-label="Sound">&#128263;</button>
{% if promos|length>1 %}<div class="pdots" id="pdots">{% for p in promos %}<i></i>{% endfor %}</div>{% endif %}</div>
<script>(function(){var tr=document.getElementById('ptrack');if(!tr)return;
var vs=[].slice.call(tr.querySelectorAll('video')),dots=[].slice.call(document.querySelectorAll('#pdots i')),cur=0,muted=true;
function show(i){cur=i;vs.forEach(function(v,k){if(k===i){v.currentTime=0;var p=v.play();if(p&&p.catch)p.catch(function(){})}else v.pause()});
dots.forEach(function(d,k){d.className=k===i?'on':''})}
function go(i){tr.scrollTo({left:i*tr.clientWidth,behavior:'smooth'})}
var tm;tr.addEventListener('scroll',function(){clearTimeout(tm);tm=setTimeout(function(){var i=Math.round(tr.scrollLeft/tr.clientWidth);if(i!==cur)show(i)},80)});
vs.forEach(function(v,k){v.addEventListener('ended',function(){if(vs.length>1&&k===cur)go((k+1)%vs.length)})});
document.getElementById('pmute').onclick=function(){muted=!muted;vs.forEach(function(v){v.muted=muted});this.innerHTML=muted?'&#128263;':'&#128266;'};
document.addEventListener('visibilitychange',function(){if(document.hidden)vs.forEach(function(v){v.pause()});else show(cur)});
show(0);})();</script>{% endif %}
{% if not me %}<div class="card"><p>{{ t('login_buy') }}</p>
<script async src="https://telegram.org/js/telegram-widget.js?22" data-telegram-login="{{ bot }}"
data-size="large" data-auth-url="/auth/telegram" data-request-access="write"></script>
{% if dev %}<p><a href="/dev-login">Dev login</a></p>{% endif %}</div>{% endif %}
<div class="grid">{% for gm in data %}<div class="gcard">{% if gm.image %}<img src="/img/{{ gm.image }}" alt="">{% endif %}
<b>{{ gm.name }}</b><small>{% if gm.stock %}{{ t('from') }} <span class="price">${{ '%.2f'|format(gm.min_price) }}</span> &middot; {{ gm.stock }} {{ t('in_stock') }}{% else %}{{ t('sold_out') }}{% endif %}</small>
<button data-game="{{ gm.id }}">{{ t('gen_keys') }}</button></div>
{% else %}<p>{{ t('no_games') }}</p>{% endfor %}</div>

<div class="ov" id="ov" hidden><div class="modal">
<div class="mh"><span>{{ t('gen_title') }}</span><button type="button" id="x" class="alt">&#10005;</button></div>
<form id="f" method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="rail" id="rail" value="balance">
<div class="mb"><label>{{ t('keys_count') }} *</label><input type="number" name="qty" id="qty" min="1" value="1">
<label>{{ t('game') }}</label><div class="dd"><button type="button" id="ddb"></button><div class="ddl" id="ddl" hidden></div></div>
<label>{{ t('duration') }}</label><div class="chips" id="dur"></div>
<label>{{ t('pay_with') }}</label><div class="chips" id="pay"></div>
<p id="tot" style="margin:16px 0 2px"></p><p id="bal" style="margin:2px 0"></p><p id="why"></p></div>
<div class="mf"><button type="button" id="setup" hidden>{{ t('setup') }}</button><button id="gen" disabled>{{ t('generate') }}</button></div></form></div></div>
<script>
(function(){
var D={{ data|tojson }}, ME={{ me_info|tojson }}, RAILS={{ rails|tojson }}, L={{ L|tojson }};
var $=function(i){return document.getElementById(i)};
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
var st={g:null,item:null,rail:'balance'};
var LBL={balance:L.balance,aba:'ABA',bakong:'Bakong'};
function money(v){return '$'+v.toFixed(2)}
function qty(){var q=parseInt($('qty').value,10);return isNaN(q)?0:q}
function openG(id){
 st.g=D.filter(function(x){return x.id===id})[0]; if(!st.g) return;
 st.item=st.g.items.filter(function(i){return i.stock>0})[0]||st.g.items[0]||null;
 st.rail='balance'; $('qty').value=1; $('ddl').hidden=true; render(); $('ov').hidden=false;
}
function render(){
 var g=st.g, b=$('ddb'); b.textContent='';
 if(g.image){var im=el('img','dimg');im.src='/img/'+g.image;b.appendChild(im)}
 b.appendChild(el('span','',g.name)); b.appendChild(el('span','car','\u25BE'));
 var l=$('ddl'); l.textContent='';
 D.forEach(function(x){var o=el('button','opt');o.type='button';
  if(x.image){var i2=el('img','dimg');i2.src='/img/'+x.image;o.appendChild(i2)}
  o.appendChild(el('span','',x.name)); o.onclick=function(){openG(x.id)}; l.appendChild(o)});
 var d=$('dur'); d.textContent='';
 g.items.forEach(function(it){var c=el('button','chip'+(st.item&&st.item.id===it.id?' on':''),it.label);
  c.type='button';c.disabled=it.stock<1;c.onclick=function(){st.item=it;render()};d.appendChild(c)});
 var p=$('pay'); p.textContent='';
 ['balance'].concat(RAILS).forEach(function(r){var c=el('button','chip'+(st.rail===r?' on':''),LBL[r]||r.toUpperCase());
  c.type='button';c.onclick=function(){st.rail=r;render()};p.appendChild(c)});
 var it=st.item,q=qty(),total=it?it.price*q:0;
 $('tot').textContent=it?(L.total+': '+money(total)+' ('+money(it.price)+' '+L.per_key+')'):L.no_stock;
 $('bal').textContent=ME.logged?(L.balance+': '+money(ME.balance)):'';
 var why='';
 if(!ME.logged) why=L.login_first;
 else if(!it||it.stock<1) why=L.sold_out;
 else if(q<1) why=L.enter_count;
 else if(q>it.stock) why=L.only_stock.replace('{n}',it.stock);
 else if(q>ME.maxqty) why=L.max_qty.replace('{n}',ME.maxqty);
 else if(st.rail==='balance' && ME.balance+1e-9<total) why=L.not_enough;
 $('why').textContent=why; $('gen').disabled=!!why; $('setup').hidden=!g.setup;
}
$('qty').oninput=render;
$('x').onclick=function(){$('ov').hidden=true};
$('ov').onclick=function(e){if(e.target===$('ov'))$('ov').hidden=true};
$('ddb').onclick=function(){$('ddl').hidden=!$('ddl').hidden};
$('setup').onclick=function(){var s=st.g.setup||'';
 if(s.indexOf('http://')===0||s.indexOf('https://')===0) window.open(s,'_blank','noopener'); else alert(s)};
$('f').onsubmit=function(){
 if($('gen').disabled||!st.item) return false;
 $('f').action=(st.rail==='balance'?'/buy/':'/pay/')+st.item.id; $('rail').value=st.rail; return true};
document.querySelectorAll('[data-game]').forEach(function(b){
 b.onclick=function(){openG(parseInt(b.getAttribute('data-game'),10))}});
})();
</script>{% endblock %}"""

ORDER = """{% extends 'base.html' %}{% block body %}
<h3>{{ t('order') }} #{{ o.id }} &mdash; {{ mtitle(o) }} x{{ o.qty }} (${{ '%.2f'|format(o.total) }})</h3>
{% for k in keys %}<div class="card"><code>{{ k }}</code></div>{% endfor %}
{% if guide %}<h3>{{ t('how_to_use') }}</h3><div class="card">
{% if guide.video %}{% if guide.video.kind=='file' %}<video src="{{ guide.video.src }}" controls playsinline preload="metadata" style="width:100%;border-radius:12px;margin-bottom:10px"></video>
{% elif guide.video.kind=='embed' %}<div style="aspect-ratio:16/9;margin-bottom:10px"><iframe src="{{ guide.video.src }}" style="width:100%;height:100%;border:0;border-radius:12px" allowfullscreen loading="lazy"></iframe></div>
{% else %}<a href="{{ guide.video.src }}" target="_blank" rel="noopener noreferrer"><button type="button">&#9654; {{ t('watch_video') }}</button></a>{% endif %}{% endif %}
{% if guide.text %}<p style="white-space:pre-wrap;margin:8px 3px">{{ guide.text }}</p>{% endif %}
{% for u in guide.links %}<a href="{{ u }}" target="_blank" rel="noopener noreferrer"><button type="button" class="alt">&#128279; {{ u|replace('https://','')|replace('http://','')|truncate(40) }}</button></a>{% endfor %}
{% if guide.file %}<a href="{{ guide.file.src }}"><button type="button">&#11015; {{ guide.file.name }}</button></a>{% endif %}
</div>{% endif %}{% endblock %}"""

ORDERS = """{% extends 'base.html' %}{% block body %}<h3>{{ t('my_orders') }}</h3>
{% if me.role=='reseller' %}<a href="/orders.csv">{{ t('export_csv') }}</a>{% endif %}
<table><tr><th>#</th><th>{{ t('mod') }}</th><th>{{ t('qty') }}</th><th>{{ t('total') }}</th></tr>
{% for o in orders %}<tr><td><a href="/order/{{ o.id }}">{{ o.id }}</a></td><td>{{ mtitle(o) }}</td>
<td>{{ o.qty }}</td><td>${{ '%.2f'|format(o.total) }}</td></tr>{% endfor %}</table>{% endblock %}"""

ADMIN = """{% extends 'base.html' %}{% block body %}
<h3>Site name &amp; videos</h3><div class="card">
<form method="post" action="/admin/promo" enctype="multipart/form-data"><input type="hidden" name="csrf" value="{{ csrf }}">
Site name: <input name="site_name" value="{{ site_name }}" maxlength="40"><br>
<small>If a Header video is set it replaces the name text at the top center.</small><br><label><input type="checkbox" name="brand_key" {{ 'checked' if brand_key }}> Remove green background of the Header video (green screen)</label>
{% for slot, label in [('brand','Header video (site name, top center)'),('1','Promo video 1'),('2','Promo video 2'),('3','Promo video 3')] %}
{% if slot=='brand' %}{% set src = brand_video %}{% else %}{% set cur = promos|selectattr('n','equalto',slot|int)|list|first %}{% set src = cur.src if cur else '' %}{% endif %}
<div style="width:100%;margin-top:10px;padding-top:8px;border-top:1px solid var(--line)"><b>{{ label }}</b><br>
{% if src %}<video class="vprev" src="{{ src }}" muted playsinline preload="metadata" controls></video>
<button class="gbtn" formaction="/admin/video/{{ slot }}/delete" formenctype="application/x-www-form-urlencoded" formnovalidate
onclick="return confirm('Delete this video?')">Delete video</button><br>{% else %}<small>empty</small><br>{% endif %}
<input type="file" name="video_{{ slot }}" accept="video/mp4,video/webm"> <small>or direct link:</small>
<input name="url_{{ slot }}" placeholder="https://.../video.mp4" style="min-width:220px"></div>{% endfor %}
<button>Save</button></form>
<small>MP4 or WEBM, max 30 MB each. Uploading or pasting a new video replaces the old one. A link must be a direct video file, not YouTube. Empty promo slots are hidden.</small></div>
<h3>Telegram links</h3><div class="card">
<form method="post" action="/admin/links"><input type="hidden" name="csrf" value="{{ csrf }}">
<input name="tg_channel" value="{{ tg_channel }}" placeholder="https://t.me/your_channel" style="min-width:240px">
<input name="tg_support" value="{{ tg_support }}" placeholder="https://t.me/your_support" style="min-width:240px">
<button>Save</button></form><small>Empty = hide the button in the menu.</small></div>
<h3>Payment (KHQR Pay)</h3><div class="card">
<form method="post" action="/admin/settings"><input type="hidden" name="csrf" value="{{ csrf }}">
API key (both rails) {{ '&#10003; set' if cfg.general else '&#10007; not set' }}
<input name="khqrpay_key" type="password" placeholder="sk_... (blank = keep)" autocomplete="off">
<label><input type="checkbox" name="clear_khqrpay_key">remove</label><br>
<small>Optional per-rail keys (override the key above):</small><br>
Bakong key {{ '&#10003;' if cfg.bakong else '&#10007;' }}
<input name="khqrpay_key_bakong" type="password" placeholder="blank = keep" autocomplete="off">
<label><input type="checkbox" name="clear_khqrpay_key_bakong">remove</label><br>
ABA key {{ '&#10003;' if cfg.aba else '&#10007;' }}
<input name="khqrpay_key_aba" type="password" placeholder="blank = keep" autocomplete="off">
<label><input type="checkbox" name="clear_khqrpay_key_aba">remove</label><br>
Enabled for customers:
<label><input type="checkbox" name="rail_bakong" {{ 'checked' if 'bakong' in cfg.on }}>Bakong</label>
<label><input type="checkbox" name="rail_aba" {{ 'checked' if 'aba' in cfg.on }}>ABA</label><br>
<button>Save</button></form>
<form method="post" action="/admin/health"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Test /health</button></form></div>
<h3>Games (category + image)</h3>
<div class="card"><form method="post" action="/admin/game" enctype="multipart/form-data"><input type="hidden" name="csrf" value="{{ csrf }}">
<input name="name" placeholder="Game name" required><input type="file" name="image" accept="image/png,image/jpeg,image/webp">
<input name="setup" placeholder="Setup link or note (optional)">
<button>Add game</button></form>
{% for gm in games %}<form method="post" action="/admin/game/{{ gm.id }}" enctype="multipart/form-data" style="margin-top:8px">
<input type="hidden" name="csrf" value="{{ csrf }}">
{% if gm.image %}<img class="thumb" src="/img/{{ gm.image }}" alt="">{% endif %}
<input name="name" value="{{ gm.name }}"><input type="file" name="image" accept="image/png,image/jpeg,image/webp">
<input name="setup" value="{{ gm.setup or '' }}" placeholder="Setup link or note">
<button>Save</button>{% if not gm.active %}<i>(hidden)</i>{% endif %}
<button class="alt" formaction="/admin/game/{{ gm.id }}/toggle" formenctype="application/x-www-form-urlencoded">Show/Hide</button>
<button formaction="/admin/game/{{ gm.id }}/delete" formenctype="application/x-www-form-urlencoded" style="background:#d63031;color:#fff"
onclick="return confirm('Delete game &quot;{{ gm.name }}&quot; and ALL its services and unsold keys? This cannot be undone.')">Delete</button></form>{% endfor %}</div>
<h3>After-purchase guide (shown with the keys)</h3>
{% for gm in games %}{% set gd = guides.get(gm.id) %}<div class="card"><b>{{ gm.name }}</b>
<form method="post" action="/admin/guide/{{ gm.id }}" enctype="multipart/form-data"><input type="hidden" name="csrf" value="{{ csrf }}">
<textarea name="text" rows="3" style="width:100%" placeholder="Instructions / description (optional)">{{ gd.text if gd and gd.text }}</textarea>
<textarea name="links" rows="2" style="width:100%" placeholder="Links, one per line (https://...)">{{ gd.links if gd and gd.links }}</textarea>
<input name="video_url" placeholder="Video link https://... (YouTube or .mp4)" style="width:100%">
<label>Or upload video (MP4/WEBM, max 30 MB) <input type="file" name="video_file" accept="video/mp4,video/webm"></label>
<label>File for buyers (zip, rar, 7z, apk, pdf, txt, ipa; max 30 MB) <input type="file" name="file"></label>
{% if gd and gd.video %}<label><input type="checkbox" name="rm_video"> Remove current video</label>{% endif %}
{% if gd and gd.file %}<label><input type="checkbox" name="rm_file"> Remove file ({{ gd.file_name }})</label>{% endif %}
<button>Save guide</button></form></div>{% else %}<p>Add a game first.</p>{% endfor %}
<h3>Add mod</h3><form method="post" action="/admin/mod"><input type="hidden" name="csrf" value="{{ csrf }}">
<select name="game_id"><option value="">Game...</option>{% for gm in games %}<option value="{{ gm.id }}">{{ gm.name }}</option>{% endfor %}</select>
<input name="duration_days" type="number" min="1" placeholder="Validity (number)"><select name="duration_unit">{% for u,l in [('hour','Hour'),('day','Day'),('month','Month')] %}<option value="{{ u }}"{{ ' selected' if u=='day' }}>{{ l }}</option>{% endfor %}</select><input name="name" placeholder="Name (optional)"><input name="price" type="number" step="0.01" placeholder="Price per key" required>
<input name="description" placeholder="Description"><button>Add</button></form>
<h3>Mods &amp; stock</h3>
{% for m in mods %}<div class="card"><b>{{ m.name }}</b> ${{ m.price }} &middot; available {{ m.stock }} / sold {{ m.sold }}
{% if not m.active %}<i>(hidden)</i>{% endif %}
<form method="post" action="/admin/keys/{{ m.id }}"><input type="hidden" name="csrf" value="{{ csrf }}">
<textarea name="keys" rows="4" style="width:100%" placeholder="One key per line&#10;KEY-001&#10;KEY-002" oninput="this.nextElementSibling.textContent=this.value.split(/\r?\n/).filter(function(x){return x.trim()}).length+' key(s) ready'"></textarea><small>0 key(s) ready</small><button>Add keys</button></form>
<form method="post" action="/admin/mod/{{ m.id }}/edit"><input type="hidden" name="csrf" value="{{ csrf }}">
<input name="duration_days" type="number" min="1" value="{{ m.duration_days or '' }}" placeholder="Validity" style="width:80px" title="Key validity"><select name="duration_unit">{% for u,l in [('hour','Hour'),('day','Day'),('month','Month')] %}<option value="{{ u }}"{{ ' selected' if u==(m.duration_unit or 'day') }}>{{ l }}</option>{% endfor %}</select>
<input name="price" type="number" step="0.01" min="0" value="{{ m.price }}" style="width:90px" title="Price per key">
<input name="name" value="{{ m.name }}"><button class="alt">Save validity/price</button></form>
<form method="post" action="/admin/mod/{{ m.id }}/game"><input type="hidden" name="csrf" value="{{ csrf }}">
<select name="game_id"><option value="">No game</option>{% for gm in games %}<option value="{{ gm.id }}" {{ 'selected' if m.game_id==gm.id }}>{{ gm.name }}</option>{% endfor %}</select><button class="alt">Set game</button></form>
<form method="post" action="/admin/mod/{{ m.id }}/toggle"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Show/Hide</button></form>
<form method="post" action="/admin/mod/{{ m.id }}/delete" onsubmit="return confirm('Delete service &quot;{{ m.name }}&quot; and its {{ m.stock }} unsold key(s)? This cannot be undone.')">
<input type="hidden" name="csrf" value="{{ csrf }}"><button style="background:#d63031;color:#fff">Delete</button></form></div>{% endfor %}
<h3>Users &amp; resellers</h3>
{% for u in users %}<div class="card">{{ u.first_name }} @{{ u.username }} <small>tg:{{ u.telegram_id }}</small> &middot; ${{ '%.2f'|format(u.balance) }}
<form method="post" action="/admin/user/{{ u.id }}"><input type="hidden" name="csrf" value="{{ csrf }}">
<select name="role">{% for r in ['user','reseller','admin'] %}<option {{ 'selected' if u.role==r }}>{{ r }}</option>{% endfor %}</select>
Discount % <input name="discount_pct" value="{{ u.discount_pct }}" style="width:60px">
Top-up <input name="topup" placeholder="0" style="width:70px">
<label><input type="checkbox" name="active" {{ 'checked' if u.active }}>active</label><button>Save</button></form>
{% if u.role=='reseller' %}<form method="post" action="/admin/price"><input type="hidden" name="csrf" value="{{ csrf }}">
<input type="hidden" name="user_id" value="{{ u.id }}"><select name="mod_id">{% for m in mods %}<option value="{{ m.id }}">{{ m.name }}</option>{% endfor %}</select>
<input name="price" placeholder="Special price (empty=remove)"><button>Set price</button></form>{% endif %}</div>{% endfor %}{% endblock %}"""

TOPUP = """{% extends 'base.html' %}{% block body %}<h3>{{ t('topup_title') }}</h3>
{% if avail %}<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
<select name="rail">{% for r in avail %}<option value="{{ r }}">{{ r|upper }}</option>{% endfor %}</select>
<input name="amount" type="number" step="0.01" min="0.01" max="500" placeholder="USD" required><button>{{ t('pay_khqr') }}</button></form>
{% else %}<p>{{ t('pay_na') }}</p>{% endif %}
<table>{% for t in recent %}<tr><td>#{{ t.id }}</td><td>{{ t.rail|upper }}</td><td>${{ '%.2f'|format(t.amount) }}</td>
<td>{{ tv('st_', t.status) }}</td></tr>{% endfor %}</table>{% endblock %}"""

TOPUP_PAY = """{% extends 'base.html' %}{% block body %}
<h3>{{ t('pay') }} ${{ '%.2f'|format(t.amount) }} ({{ t.rail|upper }})</h3>
<div id="box">{% if t.status=='Pending' %}<img src="{{ t.qr_image }}" alt="KHQR" style="max-width:300px;width:100%">
<p>{{ t('scan') }} <a href="{{ t.checkout_url }}" target="_blank" rel="noopener">{{ t('open_checkout') }}</a></p>
<p id="st">{{ t('waiting') }}</p>{% else %}<p>{{ t('status') }}: {{ tv('st_', t.status) }}</p>{% endif %}</div>
<a href="/topup">{{ t('back') }}</a>
<script>
var pending={{ 'true' if t.status=='Pending' else 'false' }};var ST={{ {'Expired':tv('st_','Expired'),'Failed':tv('st_','Failed'),'Cancelled':tv('st_','Cancelled')}|tojson }};
async function poll(){if(!pending)return;
try{var r=await fetch('/topup/{{ t.id }}/status');var j=await r.json();
if(j.status!=='Pending'){pending=false;
document.getElementById('box').innerHTML='<p><b>'+(j.status==='Paid'?{{ t('paid_ok')|tojson }}:
(j.status==='UnderPaid'?{{ t('mismatch')|tojson }}:{{ t('qr_new')|tojson }}.replace('{s}',ST[j.status]||j.status)))+'</b></p>';
if(j.status==='Paid')setTimeout(function(){location.href='/'},2000);return;}}catch(e){}
setTimeout(poll,4000);}
poll();
</script>{% endblock %}"""

CHECKOUT = """{% extends 'base.html' %}{% block body %}
<h3>{{ mtitle(c) }} x{{ c.qty }} &mdash; {{ t('pay') }} ${{ '%.2f'|format(c.total) }} ({{ c.rail|upper }})</h3>
<div id="box">{% if c.status=='Pending' %}<img src="{{ c.qr_image }}" alt="KHQR" style="max-width:300px;width:100%">
<p>{{ t('scan2') }}
<a href="{{ c.checkout_url }}" target="_blank" rel="noopener">{{ t('open_checkout') }}</a></p>
<p>{{ t('waiting') }}</p>{% elif c.status=='Paid' %}<p><a href="/order/{{ c.order_id }}">{{ t('view_keys') }}</a></p>
{% else %}<p>{{ t('status') }}: {{ tv('st_', c.status) }}</p>{% endif %}</div><a href="/">{{ t('back_shop') }}</a>
<script>
var pending={{ 'true' if c.status=='Pending' else 'false' }};var ST={{ {'Expired':tv('st_','Expired'),'Failed':tv('st_','Failed'),'Cancelled':tv('st_','Cancelled')}|tojson }};
async function poll(){if(!pending)return;
try{var r=await fetch('/checkout/{{ c.id }}/status');var j=await r.json();
if(j.status==='Paid'){location.href='/order/'+j.order_id;return;}
if(j.status!=='Pending'){pending=false;document.getElementById('box').innerHTML='<p><b>'+
(j.status==='UnderPaid'?{{ t('mismatch2')|tojson }}:{{ t('qr_retry')|tojson }}.replace('{s}',ST[j.status]||j.status))+'</b></p>';return;}}catch(e){}
setTimeout(poll,4000);}
poll();
</script>{% endblock %}"""

ACCOUNT = """{% extends 'base.html' %}{% block body %}<h3>{{ t('account') }}</h3>
<div class="card"><b>{{ me.first_name }}</b>{% if me.username %} <small>@{{ me.username }}</small>{% endif %}<br>
<small>{{ t('role') }}: {{ tv('role_', me.role) }}{% if me.role=='reseller' and me.discount_pct %} &middot; {{ t('discount') }} {{ me.discount_pct }}%{% endif %}</small>
<p>{{ t('balance') }}: <span class="price" style="font-size:24px">${{ '%.2f'|format(me.balance) }}</span></p>
<a href="/topup"><button type="button">{{ t('topup') }}</button></a><a href="/orders"><button type="button" class="alt">{{ t('orders') }}</button></a>
<p><small>{{ t('orders') }}: {{ stats.n }} &middot; {{ t('spent') }}: ${{ '%.2f'|format(stats.s) }}</small></p></div>
<h3 id="history">{{ t('history') }}</h3>
<table><tr><th>{{ t('time') }}</th><th>{{ t('type') }}</th><th>{{ t('amount') }}</th></tr>
{% for t in tx %}<tr><td>{{ fmt(t.created_at) }}</td><td>{{ tv('tx_', t.type) }}</td>
<td>{{ '%+.2f'|format(t.amount or 0) }}</td></tr>{% else %}<tr><td colspan="3"><small>{{ t('no_tx') }}</small></td></tr>{% endfor %}</table>
<h3>{{ t('topup_reqs') }}</h3>
<table>{% for t in tops %}<tr><td>#{{ t.id }}</td><td>{{ t.rail|upper }}</td><td>${{ '%.2f'|format(t.amount) }}</td><td>{{ tv('st_', t.status) }}</td></tr>
{% else %}<tr><td><small>{{ t('no_topup') }}</small></td></tr>{% endfor %}</table>{% endblock %}"""

DEV = """<form method="post"><input name="tg_id" placeholder="telegram id" required>
<input name="name" placeholder="name"><button>Login</button></form>"""

app.jinja_loader = DictLoader({"base.html": BASE, "shop.html": SHOP, "order.html": ORDER,
                               "orders.html": ORDERS, "admin.html": ADMIN, "dev.html": DEV,
                               "topup.html": TOPUP, "topup_pay.html": TOPUP_PAY,
                               "checkout.html": CHECKOUT, "account.html": ACCOUNT})

init_db()

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
