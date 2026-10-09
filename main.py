#!/usr/bin/env python3
"""Keystone - authentication & role-based access (FastAPI + SQLite + vanilla JS), one file.

Run:            python main.py
Create admin:   python main.py create-admin
Env vars:       SESSION_SECRET (required when APP_ENV=production), APP_ENV, DATABASE_PATH,
                COOKIE_SECURE=1 (HTTPS), HOST, PORT
"""
import os, re, sys, json, sqlite3, secrets, hashlib, hmac, base64, getpass, argparse
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional, Literal
from urllib.parse import quote

import bcrypt
from fastapi import FastAPI, Request, Depends, HTTPException, Query, Header
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

# ----------------------------------------------------------------- config
IS_PROD = os.environ.get("APP_ENV", "development").lower() == "production"
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "keystone.db"))
COOKIE_SECURE = IS_PROD or os.environ.get("COOKIE_SECURE", "").lower() in ("1", "true", "yes")
COOKIE = "__Host-session" if COOKIE_SECURE else "session"
SESSION_HOURS, REMEMBER_DAYS = 8, 30
MAX_FAILS, FAIL_WINDOW_MIN = 5, 15
ROLES = ("admin", "manager", "user")
PAGE_SIZE = 10


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def later(**kw):
    return (datetime.now(timezone.utc) + timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------- database
@contextmanager
def db(write=False):
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


def init_db():
    raw = sqlite3.connect(DB_PATH, timeout=15)
    try:
        raw.execute("PRAGMA journal_mode=WAL")  # must run outside a transaction
    finally:
        raw.close()
    with db(True) as c:
        schema = """
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          full_name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin','manager','user')),
          is_active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(
          id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          csrf TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS login_attempts(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ident TEXT NOT NULL, ip TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_log(
          id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER, action TEXT NOT NULL,
          target_id INTEGER, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_attempts ON login_attempts(ident, created_at);
        """
        for stmt in schema.split(";"):
            if stmt.strip():
                c.execute(stmt)
        c.execute("DELETE FROM sessions WHERE expires_at < ?", (now(),))


def audit(c, actor, action, target=None):
    c.execute("INSERT INTO audit_log(actor_id,action,target_id,created_at) VALUES(?,?,?,?)", (actor, action, target, now()))


_secret = None


def secret_key():
    global _secret
    if _secret:
        return _secret
    env = os.environ.get("SESSION_SECRET", "")
    if env:
        if IS_PROD and len(env) < 32:
            raise RuntimeError("SESSION_SECRET must be at least 32 characters in production.")
        _secret = env.encode()
    elif IS_PROD:
        raise RuntimeError("Set SESSION_SECRET before starting with APP_ENV=production.")
    else:  # development only: random secret generated once and kept in the local DB
        with db(True) as c:
            r = c.execute("SELECT v FROM settings WHERE k='dev_secret'").fetchone()
            if not r:
                c.execute("INSERT INTO settings VALUES('dev_secret',?)", (secrets.token_hex(32),))
                r = c.execute("SELECT v FROM settings WHERE k='dev_secret'").fetchone()
        _secret = r["v"].encode()
    return _secret
# --------------------------------------------------------------- security
def _pre(pw):
    return base64.b64encode(hashlib.sha256(pw.encode()).digest())  # avoids bcrypt's 72-byte limit


def hash_pw(pw):
    return bcrypt.hashpw(_pre(pw), bcrypt.gensalt(12)).decode()


def check_pw(pw, h):
    try:
        return bcrypt.checkpw(_pre(pw), h.encode())
    except ValueError:
        return False


DUMMY = None


def sid_of(token):
    return hmac.new(secret_key(), token.encode(), hashlib.sha256).hexdigest()


def load_session(request):
    token = request.cookies.get(COOKIE)
    if not token or len(token) > 100:
        return None
    with db() as c:
        r = c.execute("""SELECT s.id sid, s.csrf, s.expires_at, u.id, u.full_name, u.email, u.role,
                         u.is_active, u.created_at FROM sessions s JOIN users u ON u.id=s.user_id
                         WHERE s.id=?""", (sid_of(token),)).fetchone()
    if not r or r["expires_at"] < now() or not r["is_active"]:
        return None
    return dict(r)


def public(u):
    return {"id": u["id"], "full_name": u["full_name"], "email": u["email"], "role": u["role"],
            "is_active": bool(u["is_active"]), "created_at": u["created_at"]}


SAFE = ("GET", "HEAD", "OPTIONS")


def need(*roles):
    def dep(request: Request, x_csrf_token: Optional[str] = Header(None, alias="X-CSRF-Token")):
        a = load_session(request)
        if not a:
            raise HTTPException(401, "Your session is missing or has expired. Please sign in.")
        if a["role"] not in roles:
            raise HTTPException(403, "You do not have permission to do that.")
        if request.method not in SAFE and not (x_csrf_token and hmac.compare_digest(x_csrf_token, a["csrf"])):
            raise HTTPException(403, "Invalid or missing CSRF token.")
        return a
    return dep


# ------------------------------------------------------------- validation
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")


def v_email(v):
    v = v.strip().lower()
    if len(v) > 254 or not EMAIL_RE.match(v):
        raise ValueError("Enter a valid email address")
    return v


def v_name(v):
    v = " ".join(v.split())
    if not 2 <= len(v) <= 80 or re.search(r"[<>\x00-\x1f]", v):
        raise ValueError("Enter a name of 2 to 80 characters")
    return v


def v_pw(v):
    if not 8 <= len(v) <= 128 or not re.search(r"[A-Za-z]", v) or not re.search(r"\d", v):
        raise ValueError("Use 8+ characters with at least one letter and one number")
    return v


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")  # unknown fields such as "role" are rejected


class RegisterIn(Strict):
    full_name: str = Field(max_length=200)
    email: str = Field(max_length=300)
    password: str = Field(max_length=300)
    confirm_password: str = Field(max_length=300)
    val_name = field_validator("full_name")(lambda cls, v: v_name(v))
    val_email = field_validator("email")(lambda cls, v: v_email(v))
    val_pw = field_validator("password")(lambda cls, v: v_pw(v))

    @field_validator("confirm_password")
    @classmethod
    def same(cls, v, info):
        if v != info.data.get("password"):
            raise ValueError("Passwords do not match")
        return v


class LoginIn(Strict):
    email: str = Field(max_length=300)
    password: str = Field(min_length=1, max_length=300)


class ProfileIn(Strict):
    full_name: str = Field(max_length=200)
    val_name = field_validator("full_name")(lambda cls, v: v_name(v))


class RoleIn(Strict):
    role: Literal["admin", "manager", "user"]


class StatusIn(Strict):
    is_active: bool
    # -------------------------------------------------------------------- app
@asynccontextmanager
async def lifespan(app):
    global DUMMY
    init_db()
    secret_key()
    DUMMY = hash_pw(secrets.token_urlsafe(12))
    yield


app = FastAPI(title="Keystone Access API", version="1.0.0", lifespan=lifespan, redoc_url=None)


def err(status, msg, **kw):
    return JSONResponse({"detail": msg, **kw}, status_code=status)


@app.exception_handler(RequestValidationError)
async def on_validation(request, exc):
    errors = {}
    for e in exc.errors():
        key = str(e["loc"][-1]) if e["loc"] else "body"
        errors.setdefault(key, str(e["msg"]).replace("Value error, ", ""))
    return err(422, "Please fix the highlighted fields.", errors=errors)


@app.exception_handler(StarletteHTTPException)
async def on_http(request, exc):
    if request.url.path.startswith("/api") or request.url.path == "/health":
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))
    return error_page(request, exc.status_code)


@app.exception_handler(Exception)
async def on_crash(request, exc):
    print("Unhandled error:", type(exc).__name__)  # never print request data / secrets
    if request.url.path.startswith("/api"):
        return err(500, "Something went wrong on our side. Please try again.")
    return error_page(request, 500)


@app.middleware("http")
async def guard(request: Request, call_next):
    p = request.url.path
    if request.method not in SAFE and p.startswith("/api"):
        origin = request.headers.get("origin")
        if (origin and origin.split("://", 1)[-1] != request.headers.get("host")) or \
                request.headers.get("sec-fetch-site") == "cross-site":
            return err(403, "Cross-site request blocked.")
        if int(request.headers.get("content-length") or 0) > 20000:
            return err(413, "Request too large.")
    r = await call_next(request)
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                      "Referrer-Policy": "same-origin"})
    if p.startswith("/api"):
        r.headers["Cache-Control"] = "no-store"
    if COOKIE_SECURE:
        r.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return r


# ------------------------------------------------------------- auth routes
@app.get("/health", tags=["System"])
def health():
    with db() as c:
        c.execute("SELECT 1")
    return {"status": "ok"}


@app.post("/api/auth/register", status_code=201, tags=["Auth"])
def register(body: RegisterIn):
    h = hash_pw(body.password)
    try:
        with db(True) as c:
            ts = now()
            cur = c.execute("INSERT INTO users(full_name,email,password_hash,role,is_active,created_at,updated_at)"
                            " VALUES(?,?,?,'user',1,?,?)", (body.full_name, body.email, h, ts, ts))
            audit(c, cur.lastrowid, "register", cur.lastrowid)
    except sqlite3.IntegrityError:
        return err(409, "An account with this email already exists.", errors={"email": "Already registered"})
    return {"message": "Account created. You can sign in now."}


@app.post("/api/auth/login", tags=["Auth"])
def login(body: LoginIn, request: Request, remember: bool = False):
    email = body.email.strip().lower()[:254]
    ip = request.client.host if request.client else "?"
    with db(True) as c:
        c.execute("DELETE FROM login_attempts WHERE created_at < ?", (later(days=-1),))
        n, first = c.execute("SELECT COUNT(*), MIN(created_at) FROM login_attempts WHERE ident IN (?,?) AND created_at>?",
                             (email, "ip:" + ip, later(minutes=-FAIL_WINDOW_MIN))).fetchone()
        user = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if n >= MAX_FAILS:
        return err(429, f"Too many failed attempts. Try again in {FAIL_WINDOW_MIN} minutes.",
                   )
    ok = check_pw(body.password, user["password_hash"] if user else DUMMY) and user is not None
    if not ok:
        with db(True) as c:
            c.execute("INSERT INTO login_attempts(ident,ip,created_at) VALUES(?,?,?)", (email, ip, now()))
        return err(401, "Incorrect email or password.")
    if not user["is_active"]:
        return err(403, "This account is deactivated. Contact an administrator.")
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    days = REMEMBER_DAYS if remember else None
    with db(True) as c:
        c.execute("DELETE FROM login_attempts WHERE ident=?", (email,))
        c.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (sid_of(token), user["id"], csrf, now(),
                  later(days=REMEMBER_DAYS) if remember else later(hours=SESSION_HOURS)))
        audit(c, user["id"], "login", user["id"])
    r = JSONResponse({"user": public(user), "csrf_token": csrf})
    r.set_cookie(COOKIE, token, max_age=days and days * 86400, httponly=True, secure=COOKIE_SECURE, samesite="lax", path="/")
    return r


@app.post("/api/auth/logout", tags=["Auth"])
def logout(a=Depends(need(*ROLES))):
    with db(True) as c:
        c.execute("DELETE FROM sessions WHERE id=?", (a["sid"],))
        audit(c, a["id"], "logout", a["id"])
    r = JSONResponse({"message": "Signed out."})
    r.delete_cookie(COOKIE, path="/", secure=COOKIE_SECURE, httponly=True, samesite="lax")
    return r


@app.get("/api/auth/me", tags=["Auth"])
def me(a=Depends(need(*ROLES))):
    return {"user": public(a), "csrf_token": a["csrf"]}
# ------------------------------------------------------------ profile etc.
@app.get("/api/profile", tags=["Profile"])
def get_profile(a=Depends(need(*ROLES))):
    return public(a)


@app.patch("/api/profile", tags=["Profile"])
def update_profile(body: ProfileIn, a=Depends(need(*ROLES))):
    with db(True) as c:
        c.execute("UPDATE users SET full_name=?, updated_at=? WHERE id=?", (body.full_name, now(), a["id"]))
        audit(c, a["id"], "profile_update", a["id"])
        u = c.execute("SELECT * FROM users WHERE id=?", (a["id"],)).fetchone()
    return public(u)


@app.get("/api/users/{user_id}", tags=["Profile"])
def get_user(user_id: int, a=Depends(need(*ROLES))):
    if a["role"] != "admin" and user_id != a["id"]:
        raise HTTPException(403, "You can only view your own account.")
    with db() as c:
        u = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        raise HTTPException(404, "User not found.")
    return public(u)


def counts(c, only_user=False):
    w = "WHERE role='user'" if only_user else ""
    r = c.execute(f"""SELECT COUNT(*) total, COALESCE(SUM(role='admin'),0) admins, COALESCE(SUM(role='manager'),0) managers,
        COALESCE(SUM(role='user'),0) users, COALESCE(SUM(is_active=1),0) active, COALESCE(SUM(is_active=0),0) inactive,
        COALESCE(SUM(created_at>?),0) new_7d FROM users {w}""", (later(days=-7),)).fetchone()
    return dict(r)


@app.get("/api/dashboard/stats", tags=["Dashboard"])
def dash_stats(a=Depends(need(*ROLES))):
    with db() as c:
        sess = c.execute("SELECT COUNT(*) FROM sessions WHERE user_id=? AND expires_at>?", (a["id"], now())).fetchone()[0]
        act = [dict(r) for r in c.execute("SELECT action, created_at FROM audit_log WHERE actor_id=? ORDER BY id DESC LIMIT 6", (a["id"],))]
    return {"active_sessions": sess, "activity": act}


@app.get("/api/admin/stats", tags=["Admin"])
def admin_stats(a=Depends(need("admin"))):
    with db() as c:
        return counts(c)


@app.get("/api/manager/stats", tags=["Manager"])
def manager_stats(a=Depends(need("manager", "admin"))):
    with db() as c:
        return counts(c, True)


def search_users(a_roles_only_user, search, role, status, page):
    where, args = [], []
    if a_roles_only_user:
        where.append("role='user'")
    if role:
        where.append("role=?"); args.append(role)
    if status:
        where.append("is_active=?"); args.append(1 if status == "active" else 0)
    if search:
        s = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where.append("(full_name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\')"); args += [s, s]
    w = ("WHERE " + " AND ".join(where)) if where else ""
    with db() as c:
        total = c.execute(f"SELECT COUNT(*) FROM users {w}", args).fetchone()[0]
        rows = c.execute(f"SELECT * FROM users {w} ORDER BY id DESC LIMIT ? OFFSET ?", args + [PAGE_SIZE, (page - 1) * PAGE_SIZE]).fetchall()
    return {"items": [public(r) for r in rows], "total": total, "page": page, "pages": max(1, -(-total // PAGE_SIZE))}


Role = Optional[Literal["admin", "manager", "user"]]
Stat = Optional[Literal["active", "inactive"]]


@app.get("/api/admin/users", tags=["Admin"])
def admin_users(search: Optional[str] = Query(None, max_length=100), role: Role = None, status: Stat = None,
                page: int = Query(1, ge=1, le=100000), a=Depends(need("admin"))):
    return search_users(False, search, role, status, page)


@app.get("/api/manager/users", tags=["Manager"])
def manager_users(search: Optional[str] = Query(None, max_length=100), status: Stat = None,
                  page: int = Query(1, ge=1, le=100000), a=Depends(need("manager", "admin"))):
    return search_users(True, search, None, status, page)


def active_admins_besides(c, uid):
    return c.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1 AND id<>?", (uid,)).fetchone()[0]


@app.patch("/api/admin/users/{user_id}/role", tags=["Admin"])
def set_role(user_id: int, body: RoleIn, a=Depends(need("admin"))):
    if user_id == a["id"]:
        raise HTTPException(400, "You cannot change your own role.")
    with db(True) as c:
        t = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not t:
            raise HTTPException(404, "User not found.")
        if t["role"] == "admin" and body.role != "admin" and t["is_active"] and active_admins_besides(c, user_id) < 1:
            raise HTTPException(409, "There must always be at least one active Admin.")
        c.execute("UPDATE users SET role=?, updated_at=? WHERE id=?", (body.role, now(), user_id))
        audit(c, a["id"], "role_change", user_id)
        t = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return public(t)


def change_status(user_id, active, a, only_user):
    if user_id == a["id"]:
        raise HTTPException(400, "You cannot deactivate your own account.")
    with db(True) as c:
        t = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not t:
            raise HTTPException(404, "User not found.")
        if only_user and t["role"] != "user":
            raise HTTPException(403, "Managers can only manage Normal User accounts.")
        if not active and t["role"] == "admin" and t["is_active"] and active_admins_besides(c, user_id) < 1:
            raise HTTPException(409, "There must always be at least one active Admin.")
        c.execute("UPDATE users SET is_active=?, updated_at=? WHERE id=?", (1 if active else 0, now(), user_id))
        if not active:
            c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        audit(c, a["id"], "status_change", user_id)
        t = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return public(t)


@app.patch("/api/admin/users/{user_id}/status", tags=["Admin"])
def admin_status(user_id: int, body: StatusIn, a=Depends(need("admin"))):
    return change_status(user_id, body.is_active, a, False)


@app.patch("/api/manager/users/{user_id}/status", tags=["Manager"])
def manager_status(user_id: int, body: StatusIn, a=Depends(need("manager", "admin"))):
    return change_status(user_id, body.is_active, a, True)
# ------------------------------------------------------------------ pages
PAGES = {"/login": ("login", None), "/register": ("register", None), "/dashboard": ("dashboard", ROLES),
         "/profile": ("profile", ROLES), "/admin": ("admin", ("admin",)), "/manager": ("manager", ("manager", "admin"))}


def render(boot, status=200):
    nonce = secrets.token_urlsafe(16)
    data = json.dumps(boot).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    html = (SHELL.replace("__NONCE__", nonce).replace("__CSS__", CSS).replace("__BOOTDATA__", data).replace("__JS__", JS))
    csp = (f"default-src 'self'; script-src 'nonce-{nonce}' https://unpkg.com; style-src 'nonce-{nonce}' https://fonts.googleapis.com; "
           "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    return HTMLResponse(html, status_code=status, headers={"Content-Security-Policy": csp, "Cache-Control": "no-store"})


def error_page(request, code):
    a = load_session(request) if request.cookies.get(COOKIE) else None
    return render({"page": "error", "code": code, "signed_in": bool(a)}, code)


def serve(request, path):
    page, roles = PAGES[path]
    a = load_session(request)
    if roles is None:
        return RedirectResponse("/dashboard", 303) if a else render({"page": page})
    if not a:
        why = "expired" if request.cookies.get(COOKIE) else "required"
        r = RedirectResponse(f"/login?reason={why}&next={quote(path)}", 303)
        if why == "expired":
            r.delete_cookie(COOKIE, path="/")
        return r
    if a["role"] not in roles:
        return error_page(request, 403)
    return render({"page": page, "user": public(a), "csrf": a["csrf"]})


def make_page(path):
    def page(request: Request):
        return serve(request, path)
    return page


for _p in PAGES:
    app.add_api_route(_p, make_page(_p), methods=["GET"], response_class=HTMLResponse, include_in_schema=False)


@app.get("/", include_in_schema=False)
def home(request: Request):
    return RedirectResponse("/dashboard" if load_session(request) else "/login", 303)


SHELL = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><title>Keystone</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style nonce="__NONCE__">__CSS__</style></head><body><div id="app"></div>
<noscript>Keystone needs JavaScript enabled.</noscript>
<script nonce="__NONCE__">window.__BOOT__=__BOOTDATA__;</script>
<script src="https://unpkg.com/lucide@0.469.0/dist/umd/lucide.min.js" defer></script>
<script nonce="__NONCE__">__JS__</script></body></html>"""

CSS = r"""
:root{--bg:#0B1120;--side:#101827;--card:#151F32;--line:#22304A;--cyan:#06B6D4;--blue:#3B82F6;--text:#F8FAFC;--muted:#94A3B8;--ok:#22C55E;--err:#EF4444;
--font:'Manrope',ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 var(--font)}
h1,h2,h3,p{margin:0}a{color:var(--cyan);text-decoration:none}
:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
.ic{display:inline-flex;width:18px;height:18px}.ic svg{width:18px;height:18px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid var(--line);background:transparent;color:var(--text);font:600 14px var(--font);padding:10px 16px;border-radius:12px;cursor:pointer;transition:.15s}
.btn:hover{border-color:var(--cyan);color:var(--cyan)}.btn:disabled{opacity:.5;cursor:not-allowed}
.btn.primary{background:linear-gradient(135deg,var(--cyan),var(--blue));border:0;color:#04121c;box-shadow:0 8px 22px rgba(6,182,212,.25)}
.btn.primary:hover{color:#04121c;filter:brightness(1.08)}.btn.danger{border-color:rgba(239,68,68,.5);color:#fca5a5}.btn.danger:hover{background:var(--err);color:#fff;border-color:var(--err)}
.btn.sm{padding:6px 10px;font-size:13px;border-radius:10px}.btn.block{width:100%}
.spin{width:16px;height:16px;border:2px solid rgba(4,18,28,.3);border-top-color:#04121c;border-radius:50%;animation:sp .7s linear infinite}
.btn:not(.primary) .spin{border-color:rgba(255,255,255,.3);border-top-color:#fff}@keyframes sp{to{transform:rotate(360deg)}}
.card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 10px 30px rgba(2,6,23,.4)}
.field{margin-bottom:16px}.field label{display:block;font-weight:600;font-size:13px;margin-bottom:6px}
.wrap{position:relative}.wrap .lead{position:absolute;left:13px;top:50%;transform:translateY(-50%);color:var(--muted)}
input,select{width:100%;background:#0F1829;border:1px solid var(--line);color:var(--text);border-radius:12px;padding:11px 14px;font:inherit}
input.pad{padding-left:40px}input:focus,select:focus{border-color:var(--cyan);outline:none;box-shadow:0 0 0 3px rgba(6,182,212,.18)}
input[aria-invalid=true]{border-color:var(--err)}.fe{color:#fca5a5;font-size:12.5px;min-height:0;margin-top:4px}
.eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:0;color:var(--muted);cursor:pointer;padding:8px}
.meter{display:flex;gap:4px;margin-top:8px}.meter i{flex:1;height:4px;border-radius:4px;background:var(--line)}
.meter.s1 i:nth-child(-n+1){background:var(--err)}.meter.s2 i:nth-child(-n+2){background:#F59E0B}.meter.s3 i:nth-child(-n+3){background:var(--blue)}.meter.s4 i{background:var(--ok)}
.hint{font-size:12.5px;color:var(--muted);margin-top:4px}.check{display:flex;gap:8px;align-items:center;font-size:14px;color:var(--muted)}.check input{width:auto}
.auth{min-height:100vh;display:grid;grid-template-columns:1.1fr 1fr}.brandp{padding:56px;background:radial-gradient(900px 500px at 10% 0,rgba(6,182,212,.16),transparent),var(--side);border-right:1px solid var(--line);display:flex;flex-direction:column;justify-content:space-between}
.brandp h1{font-size:40px;line-height:1.15;font-weight:800;max-width:460px}.brandp p{color:var(--muted);max-width:420px;margin-top:14px}
.logo{display:flex;align-items:center;gap:10px;font-weight:800;font-size:18px}.mark{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--cyan),var(--blue));display:grid;place-items:center;color:#04121c}
.formp{display:grid;place-items:center;padding:32px}.formp .box{width:100%;max-width:410px}.formp h2{font-size:26px;font-weight:800}.formp .sub{color:var(--muted);margin:6px 0 24px}
.notice{padding:11px 14px;border-radius:12px;background:rgba(6,182,212,.1);border:1px solid rgba(6,182,212,.35);margin-bottom:16px;font-size:14px}.notice.bad{background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.4)}
.layout{display:grid;grid-template-columns:260px 1fr;min-height:100vh}.side{background:var(--side);border-right:1px solid var(--line);padding:20px 14px;display:flex;flex-direction:column;gap:6px;position:sticky;top:0;height:100vh}
.side .logo{padding:6px 10px 18px}.nav{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:12px;color:var(--muted);font-weight:600;border:0;background:none;font-size:15px;font-family:var(--font);cursor:pointer;text-align:left;width:100%}
.nav:hover{background:rgba(148,163,184,.08);color:var(--text)}.nav.on{background:rgba(6,182,212,.12);color:var(--cyan)}.grow{flex:1}
.top{display:flex;align-items:center;gap:12px;padding:16px 28px;border-bottom:1px solid var(--line)}.top .menu{display:none}
.icon{background:none;border:1px solid var(--line);color:var(--text);border-radius:10px;padding:8px;cursor:pointer}
.content{padding:28px;max-width:1180px}.head{margin-bottom:22px}.head h1{font-size:28px;font-weight:800}.head p{color:var(--muted)}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));margin-bottom:20px}.two{display:grid;gap:16px;grid-template-columns:1.4fr 1fr}
.stat .n{font-size:30px;font-weight:800;margin-top:4px}.stat .l{color:var(--muted);font-size:13px}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700;border:1px solid}.b-admin{color:var(--cyan);border-color:rgba(6,182,212,.5);background:rgba(6,182,212,.1)}
.b-manager{color:#93c5fd;border-color:rgba(59,130,246,.5);background:rgba(59,130,246,.1)}.b-user{color:var(--muted);border-color:var(--line)}
.b-ok{color:var(--ok);border-color:rgba(34,197,94,.4)}.b-off{color:#fca5a5;border-color:rgba(239,68,68,.4)}
.tools{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}.tools input{max-width:280px}.tools select{width:auto}
.tw{overflow-x:auto}table{width:100%;border-collapse:collapse}th{color:var(--muted);font-size:12.5px;text-align:left;padding:10px 12px;border-bottom:1px solid var(--line)}
td{padding:12px;border-bottom:1px solid var(--line);vertical-align:middle}tr:last-child td{border:0}.who{display:flex;gap:10px;align-items:center}.av{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,var(--cyan),var(--blue));color:#04121c;font-weight:800;display:grid;place-items:center;flex:none;font-size:13px}
.acts{display:flex;gap:6px;flex-wrap:wrap}.muted{color:var(--muted)}.empty{text-align:center;padding:40px 10px;color:var(--muted)}.empty h3{color:var(--text);margin:8px 0 4px}
.pager{display:flex;justify-content:space-between;align-items:center;margin-top:14px;color:var(--muted);font-size:14px}
.kv{display:grid;grid-template-columns:130px 1fr;gap:10px;padding:9px 0;border-bottom:1px solid var(--line)}.kv:last-child{border:0}.kv span:first-child{color:var(--muted)}
.ov{position:fixed;inset:0;background:rgba(2,6,23,.7);display:grid;place-items:center;padding:16px;z-index:50}.modal{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:24px;width:100%;max-width:440px}
.modal h3{font-size:19px;margin-bottom:8px}.mf{display:flex;justify-content:flex-end;gap:10px;margin-top:20px}
.toasts{position:fixed;right:16px;bottom:16px;display:flex;flex-direction:column;gap:8px;z-index:80}.toast{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--cyan);padding:12px 16px;border-radius:12px;max-width:340px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
.toast.ok{border-left-color:var(--ok)}.toast.bad{border-left-color:var(--err)}.center{min-height:100vh;display:grid;place-items:center;text-align:center;padding:24px}.center .code{font-size:72px;font-weight:800;color:var(--cyan)}
.mt0{margin:18px 0 0}.mt{margin-top:16px}.bd{display:none}@media(max-width:860px){.auth{grid-template-columns:1fr}.brandp{display:none}.layout{grid-template-columns:1fr}.side{position:fixed;z-index:60;left:0;width:270px;transform:translateX(-100%);transition:.2s}
.side.open{transform:none}.bd.open{display:block;position:fixed;inset:0;background:rgba(2,6,23,.6);z-index:55}.top .menu{display:block}.two{grid-template-columns:1fr}.content{padding:18px}.top{padding:12px 16px}.hm{display:none}}
@media(prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
"""
JS = r"""
(function(){'use strict';
const B=window.__BOOT__,$=(s,e)=>(e||document).querySelector(s),app=$('#app');let csrf=B.csrf||null;
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const G={shield:'◈',user:'●',users:'●●',eye:'◉',eyeoff:'○',mail:'✉',lock:'🔒',menu:'☰',logout:'⇥',home:'▦',brief:'▤'};
const L={shield:'shield-check',user:'user',users:'users',eye:'eye',eyeoff:'eye-off',mail:'mail',lock:'lock',menu:'menu',logout:'log-out',home:'layout-dashboard',brief:'briefcase'};
const ic=(n,c)=>`<i data-lucide="${L[n]}" class="ic ${c||''}">${G[n]}</i>`;
const icons=()=>{if(window.lucide)try{lucide.createIcons()}catch(e){}};window.addEventListener('load',icons);
const RL={admin:'Admin',manager:'Manager',user:'Normal User'};
const fd=d=>d?new Date(d).toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'}):'-';
const fdt=d=>d?new Date(d).toLocaleString():'-';
const ACT={register:'Created account',login:'Signed in',logout:'Signed out',profile_update:'Updated profile',role_change:'Changed a role',status_change:'Changed account status'};
function toast(m,t){let w=$('.toasts');if(!w){w=document.createElement('div');w.className='toasts';w.setAttribute('role','status');document.body.appendChild(w)}
const e=document.createElement('div');e.className='toast '+(t||'');e.textContent=m;w.appendChild(e);setTimeout(()=>e.remove(),4200)}
async function api(m,u,b){const h={};if(b!==undefined)h['Content-Type']='application/json';if(csrf)h['X-CSRF-Token']=csrf;let r;
try{r=await fetch(u,{method:m,headers:h,credentials:'same-origin',body:b!==undefined?JSON.stringify(b):undefined})}catch(e){throw{status:0,message:'Cannot reach the server. Check your connection.'}}
let d=null;try{d=await r.json()}catch(e){}
if(!r.ok){if(r.status===401&&B.user){location.href='/login?reason=expired'}throw{status:r.status,message:(d&&d.detail)||'Request failed.',errors:(d&&d.errors)||{}}}return d}
function modal(html,mount){const o=document.createElement('div');o.className='ov';o.innerHTML=`<div class="modal" role="dialog" aria-modal="true">${html}</div>`;document.body.appendChild(o);
const close=()=>{o.remove();document.removeEventListener('keydown',k)};const k=e=>{if(e.key==='Escape')close()};document.addEventListener('keydown',k);
o.addEventListener('click',e=>{if(e.target===o)close()});const f=$('input,select,button',o);f&&f.focus();mount&&mount(o,close);icons();return close}
function confirmBox(title,msg,okText,danger){return new Promise(res=>{modal(`<h3>${esc(title)}</h3><p class="muted">${esc(msg)}</p><div class="mf"><button class="btn" data-x="0">Cancel</button><button class="btn ${danger?'danger':'primary'}" data-x="1">${esc(okText)}</button></div>`,
(o,close)=>{o.querySelectorAll('[data-x]').forEach(b=>b.onclick=()=>{close();res(b.dataset.x==='1')})})})}
function field(id,label,type,o){o=o||{};const pw=type==='password';return `<div class="field"><label for="${id}">${esc(label)}</label><div class="wrap">${o.i?ic(o.i,'lead'):''}<input id="${id}" name="${id}" type="${type}" class="${o.i?'pad':''}" autocomplete="${o.ac||'off'}" ${o.req===false?'':'required'}>${pw?`<button type="button" class="eye" aria-label="Show password" data-eye="${id}">${ic('eye')}</button>`:''}</div><p class="fe" data-fe="${id}" role="alert"></p></div>`}
document.addEventListener('click',e=>{const b=e.target.closest('[data-eye]');if(!b)return;const i=$('#'+b.dataset.eye),s=i.type==='password';i.type=s?'text':'password';b.innerHTML=ic(s?'eyeoff':'eye');b.setAttribute('aria-label',s?'Hide password':'Show password');icons()});
function ferr(form,errs){form.querySelectorAll('[data-fe]').forEach(p=>{p.textContent='';const i=$('#'+p.dataset.fe,form);i&&i.removeAttribute('aria-invalid')});
Object.keys(errs||{}).forEach(k=>{const p=form.querySelector(`[data-fe="${k}"]`);if(p){p.textContent=errs[k];const i=$('#'+k,form);i&&i.setAttribute('aria-invalid','true')}})}
function busy(btn,on,txt){btn.disabled=on;if(on){btn.dataset.t=btn.innerHTML;btn.innerHTML='<span class="spin"></span> '+txt}else btn.innerHTML=btn.dataset.t||btn.innerHTML}
const EM=/^[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;
const strength=p=>{let s=0;if(p.length>=8)s++;if(p.length>=12)s++;if(/[a-z]/.test(p)&&/[A-Z]/.test(p))s++;if(/\d/.test(p)&&/[^A-Za-z0-9]/.test(p))s++;return Math.min(4,Math.max(p?1:0,s))};
function authShell(t,s,body,foot){app.innerHTML=`<div class="auth"><section class="brandp"><div class="logo"><span class="mark">${ic('shield')}</span>Keystone</div><div><h1>Access control that stays out of your way.</h1><p>Sign in to manage your account, or review who can do what across your team.</p></div><p class="muted">Admin, Manager and Normal User roles, enforced on the server.</p></section>
<section class="formp"><div class="box"><h2>${t}</h2><p class="sub">${s}</p>${body}<p class="sub mt0">${foot}</p></div></section></div>`;icons()}
function login(){const q=new URLSearchParams(location.search),R={expired:['Your session expired. Sign in again to continue.',1],required:['Sign in to open that page.'],logged_out:['You have been signed out.']};
let n=q.get('registered')?['Account created. Sign in to continue.']:R[q.get('reason')];
authShell('Welcome back','Sign in to your account.',`${n?`<div class="notice ${n[1]?'bad':''}">${n[0]}</div>`:''}<form id="f" novalidate>${field('email','Email','email',{i:'mail',ac:'email'})}${field('password','Password','password',{i:'lock',ac:'current-password'})}
<div class="field"><label class="check"><input type="checkbox" id="rem"> Keep me signed in for 30 days</label></div><button class="btn primary block" type="submit">Sign in</button></form>`,'New here? <a href="/register">Create an account</a>');
const f=$('#f');f.onsubmit=async e=>{e.preventDefault();const b=$('button[type=submit]',f),em=f.email.value.trim(),pw=f.password.value,er={};
if(!EM.test(em))er.email='Enter a valid email address';if(!pw)er.password='Enter your password';ferr(f,er);if(Object.keys(er).length)return;busy(b,1,'Signing in');
try{await api('POST','/api/auth/login?remember='+$('#rem').checked,{email:em,password:pw});const nx=q.get('next');location.href=['/profile','/admin','/manager','/dashboard'].includes(nx)?nx:'/dashboard'}
catch(x){busy(b,0);toast(x.message,'bad');ferr(f,x.errors)}}}
function register(){authShell('Create your account','Takes less than a minute.',`<form id="f" novalidate>${field('full_name','Full name','text',{i:'user',ac:'name'})}${field('email','Email','email',{i:'mail',ac:'email'})}
${field('password','Password','password',{i:'lock',ac:'new-password'})}<div class="meter" id="m"><i></i><i></i><i></i><i></i></div><p class="hint">8+ characters with a letter and a number.</p><br>${field('confirm_password','Confirm password','password',{i:'lock',ac:'new-password'})}
<button class="btn primary block" type="submit">Create account</button></form>`,'Already registered? <a href="/login">Sign in</a>');
const f=$('#f');f.password.oninput=()=>{$('#m').className='meter s'+strength(f.password.value)};
f.onsubmit=async e=>{e.preventDefault();const v={full_name:f.full_name.value.trim(),email:f.email.value.trim(),password:f.password.value,confirm_password:f.confirm_password.value},er={};
if(v.full_name.length<2)er.full_name='Enter your full name';if(!EM.test(v.email))er.email='Enter a valid email address';if(v.password.length<8||!/[A-Za-z]/.test(v.password)||!/\d/.test(v.password))er.password='Use 8+ characters with a letter and a number';
if(v.password!==v.confirm_password)er.confirm_password='Passwords do not match';ferr(f,er);if(Object.keys(er).length)return;const b=$('button[type=submit]',f);busy(b,1,'Creating');
try{await api('POST','/api/auth/register',v);location.href='/login?registered=1'}catch(x){busy(b,0);toast(x.message,'bad');ferr(f,x.errors)}}}
function shell(active,title,sub,inner){const u=B.user,nav=[['/dashboard','home','Dashboard'],['/profile','user','My profile']];
if(u.role!=='user')nav.push(['/manager','brief','Manager']);if(u.role==='admin')nav.push(['/admin','users','Admin']);
app.innerHTML=`<div class="layout"><div class="bd" id="bd"></div><aside class="side" id="side"><div class="logo"><span class="mark">${ic('shield')}</span>Keystone</div>
${nav.map(n=>`<a class="nav ${n[0]===active?'on':''}" href="${n[0]}">${ic(n[1])}${n[2]}</a>`).join('')}${u.role==='admin'?'<a class="nav" href="/docs" target="_blank" rel="noopener">'+ic('shield')+'API docs</a>':''}
<div class="grow"></div><button class="nav" id="out">${ic('logout')}Sign out</button></aside><div><header class="top"><button class="icon menu" id="mn" aria-label="Open menu">${ic('menu')}</button><div class="grow"></div>
<span class="badge b-${u.role}">${RL[u.role]}</span><span class="hm" id="nm">${esc(u.full_name)}</span></header><main class="content"><div class="head"><h1>${title}</h1><p>${sub}</p></div>${inner}</main></div></div>`;
const t=()=>{$('#side').classList.toggle('open');$('#bd').classList.toggle('open')};$('#mn').onclick=t;$('#bd').onclick=t;
$('#out').onclick=async()=>{try{await api('POST','/api/auth/logout')}catch(e){}location.href='/login?reason=logged_out'};icons()}
const stat=(l,n)=>`<div class="card stat"><div class="l">${l}</div><div class="n">${n}</div></div>`;
const kv=r=>r.map(x=>`<div class="kv"><span>${x[0]}</span><span>${x[1]}</span></div>`).join('');
async function dashboard(){const u=B.user;shell('/dashboard',`Welcome back, ${esc(u.full_name.split(' ')[0])}`,'Here is your account at a glance.',
`<div class="grid" id="st">${stat('Role',RL[u.role])}${stat('Status','Active')}${stat('Member since',fd(u.created_at))}</div><div class="two"><div class="card"><h3>Recent activity</h3><div id="ac" class="muted">Loading...</div></div>
<div class="card"><h3>Quick links</h3><p class="muted"><br><a href="/profile">Edit my profile</a>${u.role!=='user'?'<br><br><a href="/manager">Manager tools</a>':''}${u.role==='admin'?'<br><br><a href="/admin">User administration</a>':''}</p></div></div>
<div class="card mt"><h3>Account information</h3>${kv([['Name',esc(u.full_name)],['Email',esc(u.email)],['Role',RL[u.role]]])}</div>`);
try{const d=await api('GET','/api/dashboard/stats');$('#st').insertAdjacentHTML('beforeend',stat('Active sessions',d.active_sessions));
$('#ac').innerHTML=d.activity.length?d.activity.map(a=>`<div class="kv"><span>${esc(ACT[a.action]||a.action)}</span><span>${fdt(a.created_at)}</span></div>`).join(''):'<div class="empty"><h3>No activity yet</h3>Actions you take will show up here.</div>'}catch(e){$('#ac').textContent=e.message}}
function profile(){const u=B.user;shell('/profile','My profile','Update your personal information.',`<div class="two"><div class="card"><form id="f" novalidate>${field('full_name','Full name','text',{ac:'name'})}
<div class="kv"><span>Email</span><span>${esc(u.email)}</span></div><div class="kv"><span>Role</span><span>${RL[u.role]}</span></div><div class="kv"><span>Member since</span><span>${fd(u.created_at)}</span></div><br><button class="btn primary" type="submit">Save changes</button></form></div>
<div class="card"><h3>Your role</h3><p class="muted">Roles can only be changed by an administrator.</p></div></div>`);
const f=$('#f');f.full_name.value=u.full_name;f.onsubmit=async e=>{e.preventDefault();const b=$('button',f);ferr(f,{});busy(b,1,'Saving');
try{const r=await api('PATCH','/api/profile',{full_name:f.full_name.value.trim()});B.user=r;$('#nm').textContent=r.full_name;toast('Profile saved.','ok')}catch(x){ferr(f,x.errors);toast(x.message,'bad')}busy(b,0)}}
function people(base,admin){const s={q:'',role:'',status:'',page:1};let t;const self=B.user.id;
$('#tb').innerHTML=`<div class="tools"><input id="q" placeholder="Search name or email" aria-label="Search">${admin?'<select id="r" aria-label="Filter by role"><option value="">All roles</option><option value="admin">Admin</option><option value="manager">Manager</option><option value="user">Normal User</option></select>':''}
<select id="s" aria-label="Filter by status"><option value="">Any status</option><option value="active">Active</option><option value="inactive">Inactive</option></select></div><div class="tw" id="tbl"></div><div class="pager" id="pg"></div>`;
const load=async()=>{const p=new URLSearchParams({page:s.page});if(s.q)p.set('search',s.q);if(s.role)p.set('role',s.role);if(s.status)p.set('status',s.status);
$('#tbl').innerHTML='<div class="empty"><span class="spin"></span></div>';let d;try{d=await api('GET',base+'/users?'+p)}catch(e){$('#tbl').innerHTML=`<div class="empty"><h3>Could not load users</h3>${esc(e.message)}</div>`;return}
if(!d.items.length){$('#tbl').innerHTML='<div class="empty"><h3>No users found</h3>Try a different search or clear the filters.</div>';$('#pg').innerHTML='';return}
$('#tbl').innerHTML=`<table><thead><tr><th>User</th><th>Role</th><th>Status</th><th class="hm">Joined</th><th>Actions</th></tr></thead><tbody>${d.items.map(u=>{const me=u.id===self;return `<tr><td><div class="who"><span class="av">${esc(u.full_name.split(' ').map(w=>w[0]).slice(0,2).join('').toUpperCase())}</span><div>${esc(u.full_name)}<div class="muted">${esc(u.email)}</div></div></div></td>
<td><span class="badge b-${u.role}">${RL[u.role]}</span></td><td><span class="badge ${u.is_active?'b-ok':'b-off'}">${u.is_active?'Active':'Inactive'}</span></td><td class="hm">${fd(u.created_at)}</td>
<td><div class="acts"><button class="btn sm" data-a="v" data-i="${u.id}">View</button>${admin?`<button class="btn sm" data-a="r" data-i="${u.id}" ${me?'disabled':''}>Role</button>`:''}<button class="btn sm ${u.is_active?'danger':''}" data-a="t" data-i="${u.id}" ${me?'disabled':''}>${u.is_active?'Deactivate':'Activate'}</button></div></td></tr>`}).join('')}</tbody></table>`;
$('#pg').innerHTML=`<span>${d.total} user${d.total===1?'':'s'} - page ${d.page} of ${d.pages}</span><span class="acts"><button class="btn sm" id="pv" ${d.page<=1?'disabled':''}>Previous</button><button class="btn sm" id="nx" ${d.page>=d.pages?'disabled':''}>Next</button></span>`;
$('#pv').onclick=()=>{s.page--;load()};$('#nx').onclick=()=>{s.page++;load()};
const by=i=>d.items.find(u=>u.id==i);
$('#tbl').onclick=async e=>{const b=e.target.closest('[data-a]');if(!b)return;const u=by(b.dataset.i);
if(b.dataset.a==='v')modal(`<h3>${esc(u.full_name)}</h3>${kv([['Email',esc(u.email)],['Role',RL[u.role]],['Status',u.is_active?'Active':'Inactive'],['Joined',fdt(u.created_at)]])}<div class="mf"><button class="btn" data-c>Close</button></div>`,(o,c)=>$('[data-c]',o).onclick=c);
if(b.dataset.a==='t'){const on=!u.is_active;if(!await confirmBox((on?'Activate ':'Deactivate ')+u.full_name+'?',on?'They will be able to sign in again.':'They will be signed out and blocked from signing in.',on?'Activate':'Deactivate',!on))return;
try{await api('PATCH',`${base}/users/${u.id}/status`,{is_active:on});toast('Account '+(on?'activated.':'deactivated.'),'ok');load();stats()}catch(x){toast(x.message,'bad')}}
if(b.dataset.a==='r')modal(`<h3>Change role</h3><p class="muted">${esc(u.full_name)} is currently ${RL[u.role]}.</p><br><select id="nr">${ROLES.map(r=>`<option value="${r}" ${r===u.role?'selected':''}>${RL[r]}</option>`).join('')}</select><div class="mf"><button class="btn" data-c>Cancel</button><button class="btn primary" data-ok>Save role</button></div>`,(o,c)=>{
$('[data-c]',o).onclick=c;$('[data-ok]',o).onclick=async()=>{const r=$('#nr',o).value;if(r===u.role)return c();c();if(!await confirmBox('Change role to '+RL[r]+'?',`${u.full_name} will immediately get ${RL[r]} permissions.`,'Change role',r==='admin'))return;
try{await api('PATCH',`${base}/users/${u.id}/role`,{role:r});toast('Role updated.','ok');load();stats()}catch(x){toast(x.message,'bad')}}})}};
$('#q').oninput=e=>{clearTimeout(t);t=setTimeout(()=>{s.q=e.target.value.trim();s.page=1;load()},300)};$('#s').onchange=e=>{s.status=e.target.value;s.page=1;load()};if(admin)$('#r').onchange=e=>{s.role=e.target.value;s.page=1;load()};load()}
const ROLES=['admin','manager','user'];let stats=()=>{};
function admin(){shell('/admin','Admin dashboard','Manage accounts and roles.','<div class="grid" id="sg"></div><div class="card" id="tb"></div>');
stats=async()=>{try{const d=await api('GET','/api/admin/stats');$('#sg').innerHTML=stat('Total users',d.total)+stat('Admins',d.admins)+stat('Managers',d.managers)+stat('Normal users',d.users)+stat('Inactive',d.inactive)}catch(e){}};stats();people('/api/admin',true)}
function manager(){shell('/manager','Manager dashboard','View Normal User accounts and manage their access.','<div class="grid" id="sg"></div><div class="card" id="tb"></div>');
stats=async()=>{try{const d=await api('GET','/api/manager/stats');$('#sg').innerHTML=stat('Normal users',d.total)+stat('Active',d.active)+stat('Inactive',d.inactive)+stat('New this week',d.new_7d)}catch(e){}};stats();people('/api/manager',false)}
function errorPage(){const m={403:['Access denied','Your role does not include this page.'],404:['Page not found','That page does not exist.'],500:['Something went wrong','Please try again in a moment.']}[B.code]||['Error','Something went wrong.'];
app.innerHTML=`<div class="center"><div><div class="code">${B.code}</div><h2>${m[0]}</h2><p class="muted">${m[1]}</p><br><a class="btn primary" href="${B.signed_in?'/dashboard':'/login'}">${B.signed_in?'Back to dashboard':'Sign in'}</a></div></div>`}
({login,register,dashboard,profile,admin,manager,error:errorPage}[B.page])();
})();
"""
# -------------------------------------------------------------------- CLI
def create_admin():
    init_db()
    name = input("Full name: ")
    email = input("Email: ")
    try:
        name, email = v_name(name), v_email(email)
        pw = getpass.getpass("Password (hidden): ")
        if pw != getpass.getpass("Confirm password: "):
            raise ValueError("Passwords do not match")
        v_pw(pw)
    except ValueError as e:
        sys.exit(f"Error: {e}")
    try:
        with db(True) as c:
            ts = now()
            c.execute("INSERT INTO users(full_name,email,password_hash,role,is_active,created_at,updated_at) VALUES(?,?,?,'admin',1,?,?)",
                      (name, email, hash_pw(pw), ts, ts))
    except sqlite3.IntegrityError:
        sys.exit("Error: that email is already registered.")
    print(f"Admin created. Start the app with 'python main.py' and sign in as {email}.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Keystone access app")
    ap.add_argument("command", nargs="?", default="run", choices=["run", "create-admin"])
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    a = ap.parse_args()
    if a.command == "create-admin":
        create_admin()
    else:
        import uvicorn
        print(f"Open http://{a.host}:{a.port}  (API docs: /docs)")
        uvicorn.run(app, host=a.host, port=a.port)