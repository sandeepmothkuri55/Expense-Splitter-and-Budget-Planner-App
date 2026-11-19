import sqlite3, json, os, csv, io
from datetime import date, datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g, Response
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__, static_folder="static", static_url_path="")
SECRET = os.environ.get("SECRET_KEY", "dev-change-me")
DB = os.environ.get("DB_PATH", "expense.db")
ser = URLSafeTimedSerializer(SECRET)
CATS = ["Food","Transportation","Shopping","Education","Entertainment","Healthcare","Rent","Electricity and Bills","Travel","Others"]
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, pw TEXT);
CREATE TABLE IF NOT EXISTS categories(name TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), name TEXT, amount REAL, category TEXT, date TEXT, method TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS income(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), source TEXT, amount REAL, date TEXT);
CREATE TABLE IF NOT EXISTS budgets(user_id INTEGER REFERENCES users(id), category TEXT, amount REAL, PRIMARY KEY(user_id, category));
CREATE TABLE IF NOT EXISTS groups(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), name TEXT);
CREATE TABLE IF NOT EXISTS members(id INTEGER PRIMARY KEY, group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE, name TEXT, is_me INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS split_expenses(id INTEGER PRIMARY KEY, group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE, title TEXT, amount REAL, paid_by INTEGER REFERENCES members(id), participants TEXT, date TEXT);
CREATE TABLE IF NOT EXISTS settlements(id INTEGER PRIMARY KEY, group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE, from_m INTEGER, to_m INTEGER, amount REAL, date TEXT);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), text TEXT, kind TEXT, day TEXT, read INTEGER DEFAULT 0);
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db
@app.teardown_appcontext
def close(_):
    d = g.pop("db", None)
    if d: d.close()
def q(sql, a=(), one=False):
    rows = [dict(r) for r in db().execute(sql, a).fetchall()]
    return (rows[0] if rows else None) if one else rows
def x(sql, a=()):
    c = db().execute(sql, a); db().commit(); return c.lastrowid
def err(m, c=400): return jsonify(error=m), c
def init():
    c = sqlite3.connect(DB); c.executescript(SCHEMA)
    c.executemany("INSERT OR IGNORE INTO categories VALUES(?)", [(k,) for k in CATS]); c.commit(); c.close()
init()

def auth(f):
    @wraps(f)
    def w(*a, **k):
        try: g.uid = ser.loads(request.headers.get("Authorization","").replace("Bearer ",""), max_age=7*86400)["id"]
        except Exception: return err("Please sign in again", 401)
        return f(*a, **k)
    return w
def tok(u): return {"token": ser.dumps({"id": u["id"]}), "user": {"id": u["id"], "name": u["name"], "email": u["email"]}}

@app.get("/")
def index(): return app.send_static_file("index.html")

@app.post("/api/register")
def register():
    d = request.json or {}; n = (d.get("name") or "").strip(); e = (d.get("email") or "").strip().lower(); p = d.get("password") or ""
    if not n or "@" not in e or len(p) < 6: return err("Name, valid email and a password of 6+ characters are required")
    if q("SELECT 1 FROM users WHERE email=?", (e,)): return err("Email already registered", 409)
    uid = x("INSERT INTO users(name,email,pw) VALUES(?,?,?)", (n, e, generate_password_hash(p)))
    return jsonify(tok({"id": uid, "name": n, "email": e}))
@app.post("/api/login")
def login():
    d = request.json or {}; u = q("SELECT * FROM users WHERE email=?", ((d.get("email") or "").lower(),), True)
    if not u or not check_password_hash(u["pw"], d.get("password") or ""): return err("Incorrect email or password", 401)
    return jsonify(tok(u))
@app.route("/api/me", methods=["GET","PUT"])
@auth
def me():
    if request.method == "PUT":
        n = ((request.json or {}).get("name") or "").strip()
        if not n: return err("Name is required")
        x("UPDATE users SET name=? WHERE id=?", (n, g.uid))
    return jsonify(q("SELECT id,name,email FROM users WHERE id=?", (g.uid,), True))

def clean_exp(d):
    n = (d.get("name") or "").strip()
    try: a = round(float(d.get("amount")), 2)
    except Exception: a = 0
    if not n or a <= 0: return None, "Name and a positive amount are required"
    if d.get("category") not in CATS: return None, "Choose a valid category"
    try: datetime.strptime(d.get("date", ""), "%Y-%m-%d")
    except Exception: return None, "Enter a valid date"
    return (n, a, d["category"], d["date"], d.get("method") or "Cash", (d.get("notes") or "")[:500]), None

@app.route("/api/expenses", methods=["GET","POST"])
@auth
def expenses():
    if request.method == "POST":
        v, e = clean_exp(request.json or {})
        if e: return err(e)
        return jsonify(id=x("INSERT INTO expenses(user_id,name,amount,category,date,method,notes) VALUES(?,?,?,?,?,?,?)", (g.uid, *v))), 201
    s = "%" + request.args.get("q", "") + "%"; c = request.args.get("category", "")
    return jsonify(q("SELECT * FROM expenses WHERE user_id=? AND (name LIKE ? OR notes LIKE ?) AND (?='' OR category=?) ORDER BY date DESC,id DESC", (g.uid, s, s, c, c)))
@app.route("/api/expenses/<int:i>", methods=["PUT","DELETE"])
@auth
def expense(i):
    if not q("SELECT 1 FROM expenses WHERE id=? AND user_id=?", (i, g.uid)): return err("Not found", 404)
    if request.method == "DELETE": x("DELETE FROM expenses WHERE id=?", (i,)); return jsonify(ok=1)
    v, e = clean_exp(request.json or {})
    if e: return err(e)
    x("UPDATE expenses SET name=?,amount=?,category=?,date=?,method=?,notes=? WHERE id=?", (*v, i)); return jsonify(ok=1)

@app.route("/api/income", methods=["GET","POST"])
@auth
def incomes():
    if request.method == "POST":
        d = request.json or {}
        try: a = float(d.get("amount")); datetime.strptime(d.get("date",""), "%Y-%m-%d")
        except Exception: return err("Valid amount and date required")
        if a <= 0 or not d.get("source"): return err("Source and positive amount required")
        return jsonify(id=x("INSERT INTO income(user_id,source,amount,date) VALUES(?,?,?,?)", (g.uid, d["source"], a, d["date"]))), 201
    return jsonify(q("SELECT * FROM income WHERE user_id=? ORDER BY date DESC", (g.uid,)))

@app.route("/api/budgets", methods=["GET","PUT"])
@auth
def budgets():
    if request.method == "PUT":
        d = request.json or {}
        try: a = float(d.get("amount"))
        except Exception: return err("Enter a valid amount")
        if a < 0 or d.get("category") not in CATS + ["TOTAL"]: return err("Invalid budget")
        x("INSERT INTO budgets VALUES(?,?,?) ON CONFLICT(user_id,category) DO UPDATE SET amount=excluded.amount", (g.uid, d["category"], a))
    m = date.today().strftime("%Y-%m")
    spent = {r["category"]: r["t"] for r in q("SELECT category,SUM(amount) t FROM expenses WHERE user_id=? AND substr(date,1,7)=? GROUP BY category", (g.uid, m))}
    return jsonify([{"category": r["category"], "budget": r["amount"], "spent": spent.get(r["category"], sum(spent.values()) if r["category"] == "TOTAL" else 0)} for r in q("SELECT * FROM budgets WHERE user_id=?", (g.uid,))])

# ---- groups ----
def grp(i):
    r = q("SELECT * FROM groups WHERE id=? AND user_id=?", (i, g.uid), True)
    return r
def balances(gid):
    net = {m["id"]: 0 for m in q("SELECT id FROM members WHERE group_id=?", (gid,))}
    for e in q("SELECT * FROM split_expenses WHERE group_id=?", (gid,)):
        p = json.loads(e["participants"]); amt = round(e["amount"] * 100); base, rem = divmod(amt, len(p))
        net[e["paid_by"]] += amt
        for i, m in enumerate(p): net[m] -= base + (1 if i < rem else 0)
    for s in q("SELECT * FROM settlements WHERE group_id=?", (gid,)):
        a = round(s["amount"] * 100); net[s["from_m"]] += a; net[s["to_m"]] -= a
    d = sorted([[k, -v] for k, v in net.items() if v < 0], key=lambda t: -t[1]); c = sorted([[k, v] for k, v in net.items() if v > 0], key=lambda t: -t[1])
    out = []; i = j = 0
    while i < len(d) and j < len(c):
        a = min(d[i][1], c[j][1]); out.append({"from": d[i][0], "to": c[j][0], "amount": a / 100}); d[i][1] -= a; c[j][1] -= a
        if d[i][1] == 0: i += 1
        if c[j][1] == 0: j += 1
    return {k: v / 100 for k, v in net.items()}, out

@app.route("/api/groups", methods=["GET","POST"])
@auth
def groups():
    if request.method == "POST":
        d = request.json or {}; n = (d.get("name") or "").strip()
        if not n: return err("Group name is required")
        gid = x("INSERT INTO groups(user_id,name) VALUES(?,?)", (g.uid, n))
        x("INSERT INTO members(group_id,name,is_me) VALUES(?,?,1)", (gid, "You"))
        for m in {s.strip() for s in (d.get("members") or "").split(",") if s.strip() and s.strip().lower() != "you"}:
            x("INSERT INTO members(group_id,name) VALUES(?,?)", (gid, m))
        return jsonify(id=gid), 201
    return jsonify(q("SELECT * FROM groups WHERE user_id=?", (g.uid,)))
@app.get("/api/groups/<int:i>")
@auth
def group(i):
    if not grp(i): return err("Not found", 404)
    net, plan = balances(i)
    return jsonify(group=grp(i), members=q("SELECT * FROM members WHERE group_id=?", (i,)), balances=net, settle_plan=plan,
        expenses=[{**e, "participants": json.loads(e["participants"])} for e in q("SELECT * FROM split_expenses WHERE group_id=? ORDER BY date DESC,id DESC", (i,))],
        settlements=q("SELECT * FROM settlements WHERE group_id=? ORDER BY id DESC", (i,)))
@app.post("/api/groups/<int:i>/members")
@auth
def add_member(i):
    n = ((request.json or {}).get("name") or "").strip()
    if not grp(i): return err("Not found", 404)
    if not n: return err("Member name is required")
    return jsonify(id=x("INSERT INTO members(group_id,name) VALUES(?,?)", (i, n))), 201
@app.post("/api/groups/<int:i>/expenses")
@auth
def add_split(i):
    if not grp(i): return err("Not found", 404)
    d = request.json or {}; ids = {m["id"] for m in q("SELECT id FROM members WHERE group_id=?", (i,))}
    try: a = round(float(d.get("amount")), 2)
    except Exception: a = 0
    p = [int(m) for m in d.get("participants") or []]
    if not (d.get("title") or "").strip() or a <= 0: return err("Title and a positive amount are required")
    if d.get("paid_by") not in ids or not p or not set(p) <= ids: return err("Choose who paid and who participated")
    return jsonify(id=x("INSERT INTO split_expenses(group_id,title,amount,paid_by,participants,date) VALUES(?,?,?,?,?,?)", (i, d["title"].strip(), a, d["paid_by"], json.dumps(p), date.today().isoformat()))), 201
@app.post("/api/groups/<int:i>/settle")
@auth
def settle(i):
    if not grp(i): return err("Not found", 404)
    d = request.json or {}
    try: a = float(d.get("amount")); f = int(d.get("from")); t = int(d.get("to"))
    except Exception: return err("Invalid settlement")
    if a <= 0 or f == t: return err("Invalid settlement")
    x("INSERT INTO settlements(group_id,from_m,to_m,amount,date) VALUES(?,?,?,?,?)", (i, f, t, a, date.today().isoformat())); return jsonify(ok=1), 201

# ---- dashboard / analytics / AI ----
def mkey(back=0):
    t = date.today().replace(day=1)
    for _ in range(back): t = (t - timedelta(days=1)).replace(day=1)
    return t.strftime("%Y-%m")
def total(table, uid, m, col="amount"):
    return q(f"SELECT COALESCE(SUM({col}),0) t FROM {table} WHERE user_id=? AND substr(date,1,7)=?", (uid, m), True)["t"]
def owe_receive(uid):
    owe = rec = 0
    for gr in q("SELECT id FROM groups WHERE user_id=?", (uid,)):
        me = q("SELECT id FROM members WHERE group_id=? AND is_me=1", (gr["id"],), True)
        v = balances(gr["id"])[0].get(me["id"], 0) if me else 0
        owe += -v if v < 0 else 0; rec += v if v > 0 else 0
    return round(owe, 2), round(rec, 2)

@app.get("/api/dashboard")
@auth
def dashboard():
    m = mkey(); spent = total("expenses", g.uid, m); b = q("SELECT amount FROM budgets WHERE user_id=? AND category='TOTAL'", (g.uid,), True); b = b["amount"] if b else 0
    owe, rec = owe_receive(g.uid)
    return jsonify(budget=b, spent=spent, remaining=b - spent, pct=round(spent / b * 100, 1) if b else 0, owe=owe, receive=rec, income=total("income", g.uid, m),
        by_cat=q("SELECT category,SUM(amount) total FROM expenses WHERE user_id=? AND substr(date,1,7)=? GROUP BY category", (g.uid, m)),
        recent=q("SELECT * FROM expenses WHERE user_id=? ORDER BY date DESC,id DESC LIMIT 5", (g.uid,)))
@app.get("/api/analytics")
@auth
def analytics():
    ms = [mkey(i) for i in range(5, -1, -1)]
    since = (date.today() - timedelta(weeks=8)).isoformat()
    top = q("SELECT category,SUM(amount) total FROM expenses WHERE user_id=? AND substr(date,1,7)=? GROUP BY category ORDER BY total DESC", (g.uid, mkey()))
    return jsonify(months=ms, expense=[total("expenses", g.uid, k) for k in ms], income=[total("income", g.uid, k) for k in ms],
        weekly=q("SELECT strftime('%Y-W%W',date) w,SUM(amount) total FROM expenses WHERE user_id=? AND date>=? GROUP BY w ORDER BY w", (g.uid, since)),
        by_cat=top, top_category=top[0] if top else None)

@app.get("/api/insights")
@auth
def insights():
    cur = {r["category"]: r["t"] for r in q("SELECT category,SUM(amount) t FROM expenses WHERE user_id=? AND substr(date,1,7)=? GROUP BY category", (g.uid, mkey()))}
    prev = [total("expenses", g.uid, mkey(i)) for i in (1, 2, 3)]; hist = [p for p in prev if p > 0]; tips = []
    day = date.today().day; spent = sum(cur.values())
    pred = round(max(spent / day * 30, 0) * 0.5 + (sum(hist) / len(hist)) * 0.5, 2) if hist and spent else (round(spent / day * 30, 2) if spent else None)
    if cur:
        t = max(cur, key=cur.get); tips.append(f"Your biggest category this month is {t} (₹{cur[t]:,.0f}, {cur[t]/spent*100:.0f}% of spending).")
    for c in ("Entertainment", "Shopping", "Food"):
        if spent and cur.get(c, 0) / spent > 0.3: tips.append(f"{c} is over 30% of your spending. Consider setting a {c} budget to trim discretionary costs.")
    if hist and spent > sum(hist) / len(hist): tips.append("Spending this month already exceeds your 3-month average. Review recent purchases.")
    if not cur: tips.append("Add a few expenses and I will analyse your habits.")
    tips.append("A common guideline is the 50/30/20 split (needs/wants/savings). Adjust it to your situation.")
    return jsonify(tips=tips, prediction=pred, disclaimer="Estimates use your past data and are not guaranteed outcomes or financial advice.")

@app.get("/api/notifications")
@auth
def notifs():
    t = date.today().isoformat(); new = []
    for b in budgets().json:
        if b["budget"] > 0:
            r = b["spent"] / b["budget"]; n = "overall" if b["category"] == "TOTAL" else b["category"]
            if r > 1: new.append((f"You exceeded your {n} budget ({r*100:.0f}% used).", "budget"))
            elif r >= .8: new.append((f"You have used {r*100:.0f}% of your {n} budget.", "budget"))
    owe, rec = owe_receive(g.uid)
    if owe: new.append((f"You owe ₹{owe:,.2f} in unsettled group balances.", "group"))
    if rec: new.append((f"You are owed ₹{rec:,.2f} by group members. Send a reminder.", "group"))
    if not q("SELECT 1 FROM expenses WHERE user_id=? AND date=?", (g.uid, t)): new.append(("No expenses logged today. Add any you have.", "reminder"))
    for txt, k in new:
        if not q("SELECT 1 FROM notifications WHERE user_id=? AND text=? AND day=?", (g.uid, txt, t)): x("INSERT INTO notifications(user_id,text,kind,day) VALUES(?,?,?,?)", (g.uid, txt, k, t))
    return jsonify(q("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 20", (g.uid,)))

@app.get("/api/export.csv")
@auth
def export():
    o = io.StringIO(); w = csv.writer(o); w.writerow(["Date","Name","Category","Amount","Method","Notes"])
    for e in q("SELECT * FROM expenses WHERE user_id=? ORDER BY date", (g.uid,)): w.writerow([e["date"], e["name"], e["category"], e["amount"], e["method"], e["notes"]])
    return Response(o.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=expenses.csv"})

if __name__ == "__main__": app.run(debug=True)
