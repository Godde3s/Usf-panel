#  USF Panel v3.0.0 — Complete Single-File App
#  Compatible with HuggingFace Spaces (port 7860, python:3.11-slim)
# ============================================================

import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import socket
import sqlite3
import uuid as _uuid_mod
import uuid
import threading
import psutil
import base64
import contextlib
import logging
from datetime import datetime, timedelta
from urllib.parse import quote, urlencode
from collections import deque, defaultdict
from html import escape as _hesc

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Usf")
logger.info("Usf v3.0.0 starting")

app = FastAPI(title="Usf", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 7860)),
    "secret": os.environ.get("SECRET_KEY", "usf-default-secret-key-change-me"),
}

PANEL_VERSION = os.environ.get("PANEL_VERSION", "v3.0.0")
CORE_VERSION = os.environ.get("CORE_VERSION", "v3.0.0")
TELEGRAM_HANDLE = os.environ.get("TELEGRAM_HANDLE", "@Usf")

SERVICE_RUNNING = True
SERVICE_STARTED_AT = time.time()

# ─── SQLite ───────────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "/tmp/usf.db")
_DB_LOCK = threading.Lock()

def db_init():
    try:
        with _DB_LOCK, sqlite3.connect(DB_PATH) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
            )""")
            conn.commit()
        logger.info(f"SQLite OK: {DB_PATH}")
    except Exception as e:
        logger.warning(f"SQLite init error: {e}")

def db_set(key, value):
    try:
        with _DB_LOCK, sqlite3.connect(DB_PATH) as conn:
            conn.execute("INSERT OR REPLACE INTO kv (key, value, updated_at) VALUES (?,?,?)",
                         (key, value, datetime.now().isoformat()))
            conn.commit()
    except Exception as e:
        logger.warning(f"db_set({key}) err: {e}")

def db_get(key, default=None):
    try:
        with _DB_LOCK, sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
            return row[0] if row else default
    except Exception:
        return default

def db_delete(key):
    try:
        with _DB_LOCK, sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM kv WHERE key=?", (key,))
            conn.commit()
    except Exception:
        pass

# ─── State (locks created in lifespan) ───────────────────────────────────────
connections = {}
connection_sockets = {}
link_ip_map = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs = deque(maxlen=200)
hourly_traffic = defaultdict(int)
connection_history = deque(maxlen=1000)
http_client = None
_net_baseline = {"bytes_sent": 0, "bytes_recv": 0, "ts": time.time()}

LINKS = {}
LINKS_LOCK = None
CUSTOM_ADDRESSES = ["amazonaws.com"]
CUSTOM_ADDRESSES_LOCK = None
CUSTOM_DOMAIN = ""
CUSTOM_DOMAIN_LOCK = None

SESSIONS = {}
SESSIONS_LOCK = None
RATE_LIMITS = {}
RATE_LIMIT_LOCK = None

SESSION_COOKIE = "usf_sess"
SESSION_TTL = 60 * 60 * 24 * 7

AUTH = {}

def hash_password(pw):
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

# ─── Auth ────────────────────────────────────────────────────────────────────
async def create_session():
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token):
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

# ─── Rate Limit ──────────────────────────────────────────────────────────────
async def rate_limit_check(ip, max_req=10, window=60):
    now = time.time()
    async with RATE_LIMIT_LOCK:
        data = RATE_LIMITS.get(ip, [])
        data = [t for t in data if now - t < window]
        if len(data) >= max_req:
            RATE_LIMITS[ip] = data
            return False
        data.append(now)
        RATE_LIMITS[ip] = data
        return True

# ─── Middleware ──────────────────────────────────────────────────────────────
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def anti_fingerprint(request, call_next):
    resp = await call_next(request)
    for h in ("server", "x-powered-by", "via", "x-aspnet-version", "x-forwarded-host"):
        if h in resp.headers:
            del resp.headers[h]
    resp.headers["server"] = "Usf"
    resp.headers["x-content-type-options"] = "nosniff"
    resp.headers["x-frame-options"] = "SAMEORIGIN"
    resp.headers["referrer-policy"] = "no-referrer"
    if request.url.scheme == "https":
        resp.headers["strict-transport-security"] = "max-age=31536000; includeSubDomains"
    return resp

# ─── Helpers ─────────────────────────────────────────────────────────────────
def get_domain():
    d = os.environ.get("SPACE_HOST", "")
    if d:
        return d.replace("https://","").replace("http://","").rstrip("/")
    author = os.environ.get("SPACE_AUTHOR_NAME", "")
    name = os.environ.get("SPACE_NAME", "")
    if author and name:
        return f"{author}-{name}.hf.space"
    return "localhost"

def generate_uuid(seed=None):
    if seed is None:
        return str(uuid.uuid4())
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def _make_vless_params(domain, uid):
    return {
        "encryption": "none", "security": "tls", "type": "ws",
        "flow": "xtls-rprx-vision", "host": domain,
        "path": f"/ws/{uid}", "sni": domain,
        "fp": "chrome", "alpn": "h2,http/1.1",
        "mux": "true", "mux.max-connections": "8",
        "pbk": base64.b64encode(os.urandom(16)).decode()[:22],
    }

def generate_vless_link(uid, remark="Usf", address=None):
    domain = CUSTOM_DOMAIN or get_domain()
    addr = address or domain
    params = _make_vless_params(domain, uid)
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uid}@{addr}:443?{query}#{quote(remark)}"

def generate_all_client_links(uid, label, address=None):
    domain = CUSTOM_DOMAIN or get_domain()
    addr = address or domain
    base = generate_vless_link(uid, remark=label, address=addr)
    sub_url = f"https://{domain}/sub/{uid}"

    # Npv Tunnel: npv://uuid@host:port?params#remark
    npv_params = {
        "type": "ws", "security": "tls", "host": domain,
        "path": f"/ws/{uid}", "sni": domain,
        "fp": "chrome", "alpn": "h2,http/1.1", "flow": "xtls-rprx-vision",
        "encryption": "none", "mux": "true",
    }
    npv_q = "&".join(f"{k}={quote(str(v))}" for k, v in npv_params.items())
    npv_link = f"npv://{uid}@{addr}:443?{npv_q}#{quote(label)}"

    # Hiddify: hiddify://import/base64json
    hiddify_config = json.dumps({
        "server_address": addr, "server_port": 443, "remark": label,
        "config_type": "vless", "uuid": uid, "network": "ws",
        "security": "tls", "sni": domain, "fp": "chrome",
        "alpn": "h2,http/1.1", "path": f"/ws/{uid}",
        "flow": "xtls-rprx-vision", "multiplex": True,
    }, separators=(",", ":"))
    hiddify_b64 = base64.b64encode(hiddify_config.encode()).decode()
    hiddify_link = f"hiddify://import/{hiddify_b64}"

    # Mahsang: mahsa://base64json
    mahsang_config = json.dumps({
        "server_address": addr, "server_port": 443, "remark": label,
        "config_type": "vless", "id": uid, "network": "ws",
        "security": "tls", "sni": domain, "fp": "chrome",
        "alpn": "h2,http/1.1", "path": f"/ws/{uid}",
        "flow": "xtls-rprx-vision", "multiplex": True,
    }, separators=(",", ":"))
    mahsang_b64 = base64.b64encode(mahsang_config.encode()).decode()
    mahsang_link = f"mahsa://{mahsang_b64}"

    return {
        "V2RayN": base,
        "V2RayNG": base,
        "Streisand": base,
        "Shadowrocket": base,
        "Foxray": base,
        "Nekoray": base,
        "BS Client": base,
        "Npv Tunnel": npv_link,
        "Hiddify": hiddify_link,
        "Mahsang": mahsang_link,
        "Subscription": sub_url,
    }

def uptime_seconds():
    return int(time.time() - stats["start_time"])

def uptime():
    s = uptime_seconds()
    return f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"

def os_uptime_str():
    try:
        s = int(time.time() - psutil.boot_time())
        d, s = divmod(s, 86400)
        h, s = divmod(s, 3600)
        m = s // 60
        if d > 0: return f"{d}d {h}h {m}m"
        if h > 0: return f"{h}h {m}m"
        return f"{m}m"
    except Exception:
        return "N/A"

def parse_size_to_bytes(val, unit):
    unit = unit.upper()
    if unit == "GB": return int(val * 1073741824)
    if unit == "MB": return int(val * 1048576)
    if unit == "KB": return int(val * 1024)
    return int(val)

def compute_expiry(days):
    try:
        d = float(days or 0)
    except (TypeError, ValueError):
        d = 0
    if d <= 0: return ""
    return (datetime.now() + timedelta(days=d)).isoformat()

def is_expired(link):
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp: return False
    try:
        return datetime.now() >= datetime.fromisoformat(exp)
    except (TypeError, ValueError):
        return False

def expiry_epoch(link):
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp: return 0
    try:
        return int(datetime.fromisoformat(exp).timestamp())
    except (TypeError, ValueError):
        return 0

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            uid = generate_uuid()
            LINKS[uid] = {
                "label": "Default", "limit_bytes": 0, "used_bytes": 0,
                "max_connections": 0, "created_at": datetime.now().isoformat(),
                "active": True, "expiry": "", "speed_limit": 0, "tag": "", "note": "",
            }

def get_client_ip(ws):
    fwd = ws.headers.get("x-forwarded-for")
    if fwd: return fwd.split(",")[0].strip()
    return ws.client.host if ws.client else "unknown"

def count_connections_for_link(uid):
    return len(link_ip_map.get(uid, set()))

def remove_ip_from_link(uid, ip):
    if uid in link_ip_map:
        link_ip_map[uid].discard(ip)
        if not link_ip_map[uid]:
            link_ip_map.pop(uid, None)

async def close_connections_for_link(uid):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try: await ws.close(code=1000, reason="link deleted")
            except Exception: pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    link_ip_map.pop(uid, None)

def get_real_ips():
    ipv4, ipv6 = "", ""
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    ipv4 = a.address
                elif a.family == socket.AF_INET6 and not a.address.startswith("::1") and not a.address.startswith("fe80"):
                    ipv6 = a.address.split("%")[0]
    except Exception:
        pass
    return ipv4, ipv6

def get_net_speed():
    global _net_baseline
    try:
        nc = psutil.net_io_counters()
        now = time.time()
        elapsed = max(now - _net_baseline["ts"], 0.1)
        up = (nc.bytes_sent - _net_baseline["bytes_sent"]) / elapsed
        down = (nc.bytes_recv - _net_baseline["bytes_recv"]) / elapsed
        _net_baseline = {"bytes_sent": nc.bytes_sent, "bytes_recv": nc.bytes_recv, "ts": now}
        return nc.bytes_sent, nc.bytes_recv, up, down
    except Exception:
        return 0, 0, 0, 0

def fmt_speed(bps):
    if bps >= 1048576: return f"{bps/1048576:.2f} MB/s"
    if bps >= 1024: return f"{bps/1024:.2f} KB/s"
    return f"{bps:.0f} B/s"

def fmt_bytes(b):
    if b >= 1073741824: return f"{b/1073741824:.2f} GB"
    if b >= 1048576: return f"{b/1048576:.2f} MB"
    if b >= 1024: return f"{b/1024:.1f} KB"
    return f"{b} B"

# ─── Lifespan ────────────────────────────────────────────────────────────────
@contextlib.asynccontextmanager
async def lifespan(app):
    global LINKS_LOCK, CUSTOM_ADDRESSES_LOCK, CUSTOM_DOMAIN_LOCK
    global SESSIONS_LOCK, RATE_LIMIT_LOCK, http_client, _net_baseline
    global CUSTOM_DOMAIN, CUSTOM_ADDRESSES, AUTH

    LINKS_LOCK = asyncio.Lock()
    CUSTOM_ADDRESSES_LOCK = asyncio.Lock()
    CUSTOM_DOMAIN_LOCK = asyncio.Lock()
    SESSIONS_LOCK = asyncio.Lock()
    RATE_LIMIT_LOCK = asyncio.Lock()

    AUTH = {
        "password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin")),
        "username": os.environ.get("ADMIN_USERNAME", "admin"),
    }

    db_init()
    # Load saved state
    saved = db_get("links")
    if saved:
        try:
            async with LINKS_LOCK:
                LINKS.update(json.loads(saved))
            logger.info(f"Loaded {len(LINKS)} links")
        except Exception as e:
            logger.warning(f"Load links err: {e}")
    saved_a = db_get("addresses")
    if saved_a:
        try:
            async with CUSTOM_ADDRESSES_LOCK:
                CUSTOM_ADDRESSES = json.loads(saved_a)
        except Exception: pass
    saved_d = db_get("domain")
    if saved_d is not None:
        CUSTOM_DOMAIN = saved_d
    saved_pw = db_get("auth_hash")
    if saved_pw:
        AUTH["password_hash"] = saved_pw

    http_client = httpx.AsyncClient(
        limits=httpx.Limits(max_connections=500, max_keepalive_connections=100),
        timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=True
    )
    try:
        nc = psutil.net_io_counters()
        _net_baseline = {"bytes_sent": nc.bytes_sent, "bytes_recv": nc.bytes_recv, "ts": time.time()}
    except Exception:
        pass

    logger.info(f"Usf v3.0.0 started on port {CONFIG['port']}")

    async def keep_alive():
        while True:
            await asyncio.sleep(600)
            try:
                d = get_domain()
                if d and d != "localhost":
                    async with httpx.AsyncClient(timeout=10) as c:
                        await c.get(f"https://{d}/health")
            except Exception: pass

    async def periodic_save():
        while True:
            await asyncio.sleep(30)
            try:
                async with LINKS_LOCK:
                    db_set("links", json.dumps(LINKS, ensure_ascii=False))
                async with CUSTOM_ADDRESSES_LOCK:
                    db_set("addresses", json.dumps(CUSTOM_ADDRESSES))
                async with CUSTOM_DOMAIN_LOCK:
                    db_set("domain", CUSTOM_DOMAIN)
                db_set("auth_hash", AUTH["password_hash"])
            except Exception as e:
                logger.warning(f"Save err: {e}")

    t1 = asyncio.create_task(keep_alive())
    t2 = asyncio.create_task(periodic_save())

    yield

    t1.cancel()
    t2.cancel()
    try:
        async with LINKS_LOCK:
            db_set("links", json.dumps(LINKS, ensure_ascii=False))
        async with CUSTOM_ADDRESSES_LOCK:
            db_set("addresses", json.dumps(CUSTOM_ADDRESSES))
        async with CUSTOM_DOMAIN_LOCK:
            db_set("domain", CUSTOM_DOMAIN)
        db_set("auth_hash", AUTH["password_hash"])
    except Exception: pass
    if http_client:
        await http_client.aclose()

app.router.lifespan_context = lifespan

# ─── API Endpoints ───────────────────────────────────────────────────────────
@app.get("/")
async def root(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/dashboard")
    return RedirectResponse(url="/login")

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "?")
    if not await rate_limit_check(ip, 5, 60):
        raise HTTPException(429, "Too many attempts. Wait 60s.")
    body = await request.json()
    pw = str(body.get("password") or "")
    un = str(body.get("username") or "")
    if un and un != AUTH["username"]:
        raise HTTPException(401, "Invalid credentials")
    if hash_password(pw) != AUTH["password_hash"]:
        raise HTTPException(401, "Invalid credentials")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    is_https = request.url.scheme == "https"
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/", secure=is_https)
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    r = JSONResponse({"ok": True})
    r.delete_cookie(SESSION_COOKIE, path="/")
    return r

@app.get("/api/me")
async def api_me(request: Request):
    return {"authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE))}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    cur = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(cur) != AUTH["password_hash"]:
        raise HTTPException(400, "Current password is wrong")
    if len(new) < 4:
        raise HTTPException(400, "Password min 4 chars")
    AUTH["password_hash"] = hash_password(new)
    tok = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if tok:
            SESSIONS[tok] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/api/stats")
async def api_stats(_=Depends(require_auth)):
    cpu = psutil.cpu_percent(interval=0.1)
    vm = psutil.virtual_memory()
    ts, tr, up_bps, down_bps = get_net_speed()
    ipv4, ipv6 = get_real_ips()
    xray_up = int(time.time() - SERVICE_STARTED_AT) if SERVICE_RUNNING else 0
    try:
        sw = psutil.swap_memory()
        du = psutil.disk_usage("/")
        proc = psutil.Process()
    except Exception:
        sw = du = None
        proc = None
    return {
        "cpuUsage": round(cpu, 1),
        "ramUsage": round(vm.percent, 1),
        "ramUsed": f"{vm.used/1048576:.1f} MB",
        "ramTotal": f"{vm.total/1048576:.0f} MB",
        "uptime": os_uptime_str(),
        "xrayUptime": f"{xray_up//60}m" if xray_up < 3600 else f"{xray_up//3600}h {(xray_up%3600)//60}m" if SERVICE_RUNNING else "Stopped",
        "uploadSpeed": fmt_speed(up_bps),
        "downloadSpeed": fmt_speed(down_bps),
        "totalSent": fmt_bytes(ts),
        "totalReceived": fmt_bytes(tr),
        "ipv4": ipv4 or "N/A",
        "ipv6": ipv6 or "N/A",
        "activeConnections": len(connections),
        "totalTrafficMb": round(stats["total_bytes"] / 1048576, 2),
        "totalRequests": stats["total_requests"],
        "linksCount": len(LINKS),
        "domain": get_domain(),
        "hourlyTraffic": dict(hourly_traffic),
        "recentErrors": list(error_logs)[-5:],
        "cpuCores": psutil.cpu_count(logical=True) or 1,
        "swapUsage": round(sw.percent, 1) if sw else 0,
        "swapUsed": fmt_bytes(sw.used) if sw else "0 B",
        "swapTotal": fmt_bytes(sw.total) if sw else "0 B",
        "storageUsage": round(du.percent, 1) if du else 0,
        "storageUsed": fmt_bytes(du.used) if du else "0 B",
        "storageTotal": fmt_bytes(du.total) if du else "0 B",
        "appRam": f"{proc.memory_info().rss/1048576:.2f} MB" if proc else "N/A",
        "xrayRunning": SERVICE_RUNNING,
        "panelVersion": PANEL_VERSION,
        "coreVersion": CORE_VERSION,
        "telegram": TELEGRAM_HANDLE,
    }

@app.get("/api/service")
async def service_status(_=Depends(require_auth)):
    return {"running": SERVICE_RUNNING, "active_connections": len(connections)}

@app.post("/api/service/stop")
async def service_stop(_=Depends(require_auth)):
    global SERVICE_RUNNING
    SERVICE_RUNNING = False
    for ws in list(connection_sockets.values()):
        try: await ws.close(code=1012, reason="stopped")
        except: pass
    connections.clear(); connection_sockets.clear(); link_ip_map.clear()
    return {"ok": True, "running": False}

@app.post("/api/service/restart")
async def service_restart(_=Depends(require_auth)):
    global SERVICE_RUNNING, SERVICE_STARTED_AT
    SERVICE_RUNNING = False
    for ws in list(connection_sockets.values()):
        try: await ws.close(code=1012, reason="restarting")
        except: pass
    connections.clear(); connection_sockets.clear(); link_ip_map.clear()
    await asyncio.sleep(0.3)
    SERVICE_RUNNING = True
    SERVICE_STARTED_AT = time.time()
    return {"ok": True, "running": True}

@app.get("/api/logs")
async def get_logs(_=Depends(require_auth)):
    return {
        "running": SERVICE_RUNNING,
        "totals": {"bytes": stats["total_bytes"], "requests": stats["total_requests"], "errors": stats["total_errors"]},
        "errors": list(error_logs)[-50:],
        "connections": [{"id": c, "uuid": i.get("uuid"), "ip": i.get("ip"),
                         "connected_at": i.get("connected_at"), "bytes": i.get("bytes", 0)}
                        for c, i in connections.items()],
        "history": list(connection_history)[-50:],
    }

@app.get("/api/config")
async def get_config(_=Depends(require_auth)):
    async with LINKS_LOCK:
        inbounds = [{"uuid": u, "remark": d["label"], "enabled": d["active"], "ws_path": f"/ws/{u}"} for u, d in LINKS.items()]
    return {"panel": "Usf", "version": PANEL_VERSION, "running": SERVICE_RUNNING,
            "domain": CUSTOM_DOMAIN or get_domain(), "inbounds": inbounds,
            "clean_addresses": list(CUSTOM_ADDRESSES)}

@app.get("/api/backup")
async def download_backup(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links_copy = {u: dict(d) for u, d in LINKS.items()}
    backup = {"panel": "Usf", "version": PANEL_VERSION, "exported_at": datetime.now().isoformat(),
              "domain": CUSTOM_DOMAIN, "addresses": list(CUSTOM_ADDRESSES),
              "username": AUTH["username"], "password_hash": AUTH["password_hash"], "links": links_copy}
    content = json.dumps(backup, indent=2)
    fname = f"Usf-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    return Response(content=content, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})

@app.post("/api/restore")
async def restore_backup(request: Request, _=Depends(require_auth)):
    global CUSTOM_DOMAIN
    body = await request.json()
    links = body.get("links")
    if not isinstance(links, dict):
        raise HTTPException(400, "Invalid backup")
    async with LINKS_LOCK:
        LINKS.clear()
        for uid, d in links.items():
            if not isinstance(d, dict): continue
            LINKS[uid] = {
                "label": str(d.get("label", "Restored"))[:60],
                "limit_bytes": int(d.get("limit_bytes", 0) or 0),
                "used_bytes": int(d.get("used_bytes", 0) or 0),
                "max_connections": int(d.get("max_connections", 0) or 0),
                "created_at": d.get("created_at", datetime.now().isoformat()),
                "active": bool(d.get("active", True)),
                "expiry": d.get("expiry", ""),
                "speed_limit": int(d.get("speed_limit", 0) or 0),
                "tag": str(d.get("tag", ""))[:30],
                "note": str(d.get("note", ""))[:200],
            }
    if isinstance(body.get("addresses"), list):
        async with CUSTOM_ADDRESSES_LOCK:
            CUSTOM_ADDRESSES = [a for a in body["addresses"] if isinstance(a, str) and a]
    if isinstance(body.get("domain"), str):
        async with CUSTOM_DOMAIN_LOCK:
            CUSTOM_DOMAIN = body["domain"]
    return {"ok": True, "restored": len(LINKS)}

# ─── Links CRUD ──────────────────────────────────────────────────────────────
@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not label or not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(400, "Name required. Only English letters, numbers, - _ . space")
    async with LINKS_LOCK:
        if any(d["label"].lower() == label.lower() for d in LINKS.values()):
            raise HTTPException(400, "Name already exists")
    lv = float(body.get("limit_value") or 0)
    lu = body.get("limit_unit") or "GB"
    limit_bytes = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
            "max_connections": int(body.get("max_connections") or 0),
            "created_at": datetime.now().isoformat(), "active": True,
            "expiry": compute_expiry(body.get("expiry_days")),
            "speed_limit": int(body.get("speed_limit") or 0),
            "tag": str(body.get("tag") or "")[:30],
            "note": str(body.get("note") or "")[:200],
        }
    return {"uuid": uid, "label": label, "ok": True}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, d in LINKS.items():
            client_links = generate_all_client_links(uid, d["label"])
            result.append({
                "uuid": uid, "label": d["label"],
                "limit_bytes": d["limit_bytes"], "used_bytes": d["used_bytes"],
                "max_connections": d.get("max_connections", 0),
                "active": d["active"], "expiry": d.get("expiry", ""),
                "expired": is_expired(d), "created_at": d["created_at"],
                "current_connections": count_connections_for_link(uid),
                "client_links": client_links,
                "sub_url": client_links["Subscription"],
                "vless_link": client_links["V2RayN"],
                "speed_limit": d.get("speed_limit", 0),
                "tag": d.get("tag", ""), "note": d.get("note", ""),
            })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.get("/api/inbounds")
async def list_inbounds(_=Depends(require_auth)):
    r = (await list_links(_))["links"]
    for item in r:
        item["id"] = item["uuid"]
        item["remark"] = item["label"]
        item["protocol"] = "vless"
        item["enabled"] = item["active"]
        item["total_flow"] = item["limit_bytes"] / 1073741824 if item["limit_bytes"] > 0 else 0
        item["clients"] = [{"id": item["uuid"], "email": item["label"]}]
    return {"items": r, "total": len(r)}

@app.patch("/api/inbounds/{uid}")
@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(404, "Not found")
        d = LINKS[uid]
        if "active" in body: d["active"] = bool(body["active"])
        if "enabled" in body: d["active"] = bool(body["enabled"])
        if "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            lu = body.get("limit_unit") or "GB"
            d["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
        if body.get("reset_usage"): d["used_bytes"] = 0
        if "expiry_days" in body: d["expiry"] = compute_expiry(body.get("expiry_days"))
        if "label" in body: d["label"] = str(body["label"])[:60]
        if "remark" in body: d["label"] = str(body["remark"])[:60]
        if "max_connections" in body: d["max_connections"] = max(int(body["max_connections"] or 0), 0)
        if "speed_limit" in body: d["speed_limit"] = int(body["speed_limit"] or 0)
        if "tag" in body: d["tag"] = str(body.get("tag", ""))[:30]
        if "note" in body: d["note"] = str(body.get("note", ""))[:200]
    return {"ok": True}

@app.delete("/api/inbounds/{uid}")
@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

# ─── Domain & Addresses ──────────────────────────────────────────────────────
@app.get("/api/domain")
async def get_domain_api(_=Depends(require_auth)):
    return {"domain": CUSTOM_DOMAIN}

@app.post("/api/domain")
async def set_domain(request: Request, _=Depends(require_auth)):
    global CUSTOM_DOMAIN
    body = await request.json()
    d = (body.get("domain") or "").strip().lower().replace("https://","").replace("http://","").rstrip("/")
    if d and not re.match(r'^[a-z0-9\-_.]+$', d):
        raise HTTPException(400, "Invalid domain")
    async with CUSTOM_DOMAIN_LOCK:
        CUSTOM_DOMAIN = d
    return {"ok": True}

@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    a = (body.get("address") or "").strip()
    if not a: raise HTTPException(400, "Address required")
    async with CUSTOM_ADDRESSES_LOCK:
        if a in CUSTOM_ADDRESSES: raise HTTPException(400, "Already exists")
        CUSTOM_ADDRESSES.append(a)
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            CUSTOM_ADDRESSES.pop(index)
        else:
            raise HTTPException(404, "Not found")
    return {"ok": True}

# ─── Subscription ────────────────────────────────────────────────────────────
@app.get("/api/links/{uid}/sub")
async def get_sub_info(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link: raise HTTPException(404, "Not found")
    return {
        "client_links": generate_all_client_links(uid, link["label"]),
        "used_bytes": link["used_bytes"], "limit_bytes": link["limit_bytes"],
        "used_mb": round(link["used_bytes"] / 1048576, 2),
        "limit_mb": round(link["limit_bytes"] / 1048576, 2) if link["limit_bytes"] > 0 else 0,
        "remaining_mb": round((link["limit_bytes"] - link["used_bytes"]) / 1048576, 2) if link["limit_bytes"] > 0 else 0,
        "usage_percent": round((link["used_bytes"] / link["limit_bytes"]) * 100, 1) if link["limit_bytes"] > 0 else 0,
        "active": link["active"], "expired": is_expired(link),
        "expiry": link.get("expiry", ""),
        "label": link["label"],
        "sub_url": f"https://{get_domain()}/sub/{uid}",
        "speed_limit": link.get("speed_limit", 0),
        "current_connections": count_connections_for_link(uid),
    }

@app.get("/sub/{uid}")
async def sub_endpoint(uid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link: raise HTTPException(404, "Not found")
    if not link["active"]: raise HTTPException(403, "Disabled")
    if is_expired(link): raise HTTPException(403, "Expired")
    async with CUSTOM_ADDRESSES_LOCK:
        addrs = list(CUSTOM_ADDRESSES)
    links_list = [generate_vless_link(uid, remark=f"{link['label']}-Server")]
    for i, a in enumerate(addrs):
        links_list.append(generate_vless_link(uid, remark=f"{link['label']}-IP{i+1}", address=a))
    encoded = base64.b64encode("\n".join(links_list).encode()).decode()
    return Response(
        content=encoded,
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Disposition": "attachment; filename=\"sub.txt\"",
            "profile-update-interval": "6",
            "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={link['limit_bytes']}; expire={expiry_epoch(link)}",
            "profile-title": link["label"],
        }
    )

# ─── Panel Builder ───────────────────────────────────────────────────────────
@app.post("/api/panel-builder/deploy")
async def panel_builder_deploy(request: Request, _=Depends(require_auth)):
    try:
        from huggingface_hub import HfApi
    except ImportError:
        raise HTTPException(500, "huggingface_hub not installed. Install it: pip install huggingface_hub")
    body = await request.json()
    token = (body.get("hf_token") or "").strip()
    space = (body.get("space_name") or "").strip().lower()
    admin_user = (body.get("admin_username") or "admin").strip()[:30]
    admin_pass = (body.get("admin_password") or "admin").strip()
    if not token: raise HTTPException(400, "HF token required")
    if not space or not re.match(r'^[a-z0-9][a-z0-9\-_.]{0,98}[a-z0-9]$', space):
        raise HTTPException(400, "Invalid space name")
    if len(admin_pass) < 4: raise HTTPException(400, "Password min 4 chars")
    try:
        api = HfApi(token=token)
        me = api.whoami()
        repo_id = f"{me['name']}/{space}"
        import inspect
        app_file = inspect.getfile(lambda: None)
        with open(app_file, 'r') as f:
            code = f.read()
        # Replace default secret with new one
        new_secret = secrets.token_urlsafe(32)
        code = code.replace("usf-default-secret-key-change-me", new_secret)
        dockerfile = f"""FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 7860
ENV ADMIN_USERNAME={admin_user}
ENV ADMIN_PASSWORD={admin_pass}
ENV SECRET_KEY={new_secret}
CMD ["python", "-c", "import uvicorn; uvicorn.run('app:app', host='0.0.0.0', port=7860, log_level='info', access_log=False)"]
"""
        reqs = "fastapi>=0.115.0\nuvicorn>=0.30.0\nhttpx>=0.27.0\npsutil>=5.9.0\n"
        readme = f"---\ntitle: {space}\nsdk: docker\napp_port: 7860\n---\n"
        api.create_repo(repo_id=repo_id, repo_type="space", exist_ok=True, space_sdk="docker")
        for fname, content in [("app.py", code.encode()), ("Dockerfile", dockerfile.encode()),
                                ("requirements.txt", reqs.encode()), ("README.md", readme.encode())]:
            api.upload_file(path_or_fileobj=content, path_in_repo=fname, repo_id=repo_id, repo_type="space")
        return {"ok": True, "space_url": f"https://huggingface.co/spaces/{repo_id}",
                "app_url": f"https://{repo_id.split('/')[1]}.hf.space", "repo_id": repo_id}
    except Exception as e:
        raise HTTPException(500, str(e))

# ─── WebSocket Tunnel ───────────────────────────────────────────────────────
RELAY_BUF = 1024 * 1024  # 1MB for better throughput

async def parse_vless_header(chunk):
    if len(chunk) < 26: raise ValueError("too small")
    p = 0
    p += 1 + 16  # version(1) + uuid(16)
    addon_len = chunk[p]; p += 1 + addon_len
    cmd = chunk[p]; p += 1
    # VLESS spec: after command comes address TYPE, then ADDRESS, then PORT
    atype = chunk[p]; p += 1
    if atype == 1:  # IPv4
        if len(chunk) < p + 4 + 2: raise ValueError("truncated IPv4")
        addr = ".".join(str(b) for b in chunk[p:p+4]); p += 4
    elif atype == 2:  # Domain
        dl = chunk[p]; p += 1
        if len(chunk) < p + dl + 2: raise ValueError("truncated domain")
        addr = chunk[p:p+dl].decode("utf-8", errors="ignore"); p += dl
    elif atype == 3:  # IPv6
        if len(chunk) < p + 16 + 2: raise ValueError("truncated IPv6")
        ab = chunk[p:p+16]; p += 16
        addr = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {atype}")
    if len(chunk) < p + 2: raise ValueError("truncated port")
    port = int.from_bytes(chunk[p:p+2], "big"); p += 2
    return cmd, addr, port, chunk[p:]

async def check_and_add_usage(uid, n):
    """Combined quota check + usage update in a single lock acquisition."""
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"] or is_expired(link): return False
        if link["limit_bytes"] > 0 and (link["used_bytes"] + n) > link["limit_bytes"]:
            return False
        link["used_bytes"] += n
        return True

async def check_quota(uid, n):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"] or is_expired(link): return False
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + n) <= link["limit_bytes"]

async def add_usage(uid, n):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

def _get_speed_limit_bps(uid):
    """Return speed limit in bytes/sec for a link, 0 = unlimited."""
    link = LINKS.get(uid)
    if not link: return 0
    sl = link.get("speed_limit", 0)
    if sl <= 0: return 0
    # speed_limit is in Mbps, convert to bytes/sec
    return int(sl * 1024 * 1024 / 8)

async def ws_to_tcp(ws, writer, cid, uid):
    """WS -> TCP relay with batched usage tracking to reduce lock contention."""
    limit_bps = _get_speed_limit_bps(uid)
    local_bytes = 0
    BATCH = 65536
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            sz = len(data)
            local_bytes += sz
            if local_bytes >= BATCH:
                if not await check_and_add_usage(uid, local_bytes):
                    await ws.close(1008, "quota exceeded"); break
                stats["total_bytes"] += local_bytes; stats["total_requests"] += 1
                if cid in connections: connections[cid]["bytes"] += local_bytes
                hourly_traffic[datetime.now().strftime("%H:00")] += local_bytes
                local_bytes = 0
            if limit_bps > 0:
                sleep_time = sz / limit_bps
                if sleep_time > 0.01: await asyncio.sleep(sleep_time)
            writer.write(data); await writer.drain()
    except WebSocketDisconnect: pass
    finally:
        if local_bytes > 0:
            stats["total_bytes"] += local_bytes; stats["total_requests"] += 1
            if cid in connections: connections[cid]["bytes"] += local_bytes
            hourly_traffic[datetime.now().strftime("%H:00")] += local_bytes
            await add_usage(uid, local_bytes)
        try: writer.write_eof()
        except: pass

async def tcp_to_ws(ws, reader, cid, uid):
    """TCP -> WS relay with batched usage tracking."""
    limit_bps = _get_speed_limit_bps(uid)
    first = True
    local_bytes = 0
    BATCH = 65536
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            sz = len(data)
            local_bytes += sz
            if local_bytes >= BATCH:
                if not await check_and_add_usage(uid, local_bytes):
                    await ws.close(1008, "quota exceeded"); break
                stats["total_bytes"] += local_bytes
                if cid in connections: connections[cid]["bytes"] += local_bytes
                hourly_traffic[datetime.now().strftime("%H:00")] += local_bytes
                local_bytes = 0
            if limit_bps > 0:
                sleep_time = sz / limit_bps
                if sleep_time > 0.01: await asyncio.sleep(sleep_time)
            await ws.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except: pass
    finally:
        if local_bytes > 0:
            stats["total_bytes"] += local_bytes
            if cid in connections: connections[cid]["bytes"] += local_bytes
            hourly_traffic[datetime.now().strftime("%H:00")] += local_bytes
            await add_usage(uid, local_bytes)

@app.websocket("/ws/{uid}")
async def ws_tunnel(ws: WebSocket, uid: str):
    await ensure_default_link()
    await ws.accept()
    writer = None
    cid = None
    client_ip = get_client_ip(ws)
    try:
        if not SERVICE_RUNNING:
            await ws.close(1012, "stopped"); return
        async with LINKS_LOCK:
            ld = LINKS.get(uid)
            if not ld or not ld["active"]:
                await ws.close(1008, "disabled"); return
            if is_expired(ld):
                await ws.close(1008, "expired"); return
            mc = ld.get("max_connections", 0)
        if mc > 0:
            if client_ip not in link_ip_map.get(uid, set()):
                if count_connections_for_link(uid) >= mc:
                    await ws.close(1008, "limit reached"); return
        first_msg = await asyncio.wait_for(ws.receive(), timeout=15)
        if first_msg["type"] == "websocket.disconnect": return
        chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not chunk: return
        cmd, addr, port, payload = await parse_vless_header(chunk)
        cid = secrets.token_urlsafe(8)
        connections[cid] = {"uuid": uid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[cid] = ws
        link_ip_map[uid].add(client_ip)
        async with LINKS_LOCK:
            lbl = LINKS.get(uid, {}).get("label", "?")
        connection_history.append({"time": datetime.now().isoformat(), "uuid": uid[:8], "label": lbl, "ip": client_ip, "target": f"{addr}:{port}"})
        sz = len(chunk)
        stats["total_bytes"] += sz; stats["total_requests"] += 1
        connections[cid]["bytes"] += sz
        hourly_traffic[datetime.now().strftime("%H:00")] += sz
        await add_usage(uid, sz)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(addr, port), timeout=10)
        try:
            sock = writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                try: sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
                except (AttributeError, OSError): pass
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
                except (AttributeError, OSError): pass
        except: pass
        if payload:
            psz = len(payload)
            stats["total_bytes"] += psz; connections[cid]["bytes"] += psz
            hourly_traffic[datetime.now().strftime("%H:00")] += psz
            await add_usage(uid, psz)
            writer.write(payload); await writer.drain()
        t1 = asyncio.create_task(ws_to_tcp(ws, writer, cid, uid))
        t2 = asyncio.create_task(tcp_to_ws(ws, reader, cid, uid))
        done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        if cid:
            info = connections.pop(cid, None)
            connection_sockets.pop(cid, None)
            if info:
                u, ip = info.get("uuid"), info.get("ip")
                if u and ip and not any(c.get("uuid") == u and c.get("ip") == ip for c in connections.values()):
                    remove_ip_from_link(u, ip)

# ─── HTML: Status 404 ────────────────────────────────────────────────────────
STATUS_404 = r'''<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>لینک نامعتبر</title>
<style>*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e1a;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;font-family:system-ui,sans-serif}
.box{background:rgba(20,27,45,0.7);backdrop-filter:blur(24px);border:1px solid rgba(99,102,241,0.15);border-radius:24px;padding:48px 36px;text-align:center;max-width:400px;width:100%;box-shadow:0 25px 50px -12px rgba(0,0,0,0.6)}
.icon{width:56px;height:56px;border-radius:50%;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.2);display:flex;align-items:center;justify-content:center;margin:0 auto 16px;color:#ef4444;font-size:24px}
h1{color:#f1f5f9;font-size:18px;margin-bottom:8px;font-weight:700}
p{color:#94a3b8;font-size:13px;line-height:1.7}</style></head><body>
<div class="box"><div class="icon">&#10005;</div><h1>لینک نامعتبر است</h1><p>این اشتراک وجود ندارد یا حذف شده است.</p></div>
</body></html>'''

# ─── HTML: Status/Subscription Page ─────────────────────────────────────────
STATUS_HTML = r'''<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,viewport-fit=cover">
<meta name="theme-color" content="#0b0f1a">
<title>__TITLE__</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
:root{--bg:#0b0f1a;--card:rgba(15,23,42,0.6);--accent:#6366f1;--accent2:#818cf8;
--accent-soft:rgba(99,102,241,0.12);--accent-glow:rgba(99,102,241,0.3);
--text:#f1f5f9;--text2:#cbd5e1;--text3:#94a3b8;
--border:rgba(99,102,241,0.18);--border-s:rgba(255,255,255,0.06);
--green:#22c55e;--red:#ef4444;--amber:#f59e0b;--radius:16px}
html[data-theme="light"]{--bg:#f1f5f9;--card:rgba(255,255,255,0.85);--text:#0f172a;--text2:#334155;--text3:#64748b;--border:rgba(99,102,241,0.25);--border-s:rgba(0,0,0,0.06)}
html,body{height:100%}
body{font-family:'Vazirmatn',system-ui,sans-serif;font-size:16px;line-height:1.7;color:var(--text);background:var(--bg);display:flex;align-items:center;justify-content:center;padding:16px;padding:env(safe-area-inset-top) 16px env(safe-area-inset-bottom);overflow-y:auto}
.orbs{position:fixed;inset:0;z-index:0;overflow:hidden;pointer-events:none}
.orb{position:absolute;border-radius:50%;filter:blur(100px);opacity:.18;animation:orb-float 20s ease-in-out infinite}
.orb-1{width:340px;height:340px;background:#6366f1;top:-80px;right:-60px}
.orb-2{width:280px;height:280px;background:#06b6d4;bottom:-60px;left:-40px;animation-delay:-7s}
.orb-3{width:200px;height:200px;background:#8b5cf6;top:50%;left:50%;transform:translate(-50%,-50%);animation-delay:-14s}
@keyframes orb-float{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(30px,-20px) scale(1.05)}66%{transform:translate(-20px,15px) scale(.95)}}
.card{position:relative;z-index:1;background:var(--card);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border:1px solid var(--border);border-radius:var(--radius);padding:32px 24px;max-width:420px;width:100%;box-shadow:0 25px 50px -12px rgba(0,0,0,0.4)}
@media(min-width:480px){.card{padding:40px 32px}}
.header{text-align:center;margin-bottom:24px}
.logo{width:64px;height:64px;border-radius:50%;background:linear-gradient(135deg,#6366f1,#06b6d4);display:flex;align-items:center;justify-content:center;margin:0 auto 12px;font-size:28px;font-weight:800;color:#fff;box-shadow:0 0 30px var(--accent-glow)}
.header h1{font-size:20px;font-weight:700;margin-bottom:4px}
.header .sub{color:var(--text3);font-size:13px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:4px 14px;border-radius:20px;font-size:12px;font-weight:600;margin:8px 0 16px}
.badge-active{background:rgba(34,197,94,0.12);color:#22c55e;border:1px solid rgba(34,197,94,0.2)}
.badge-expired{background:rgba(239,68,68,0.12);color:#ef4444;border:1px solid rgba(239,68,68,0.2)}
.badge-disabled{background:rgba(100,116,139,0.12);color:#94a3b8;border:1px solid rgba(100,116,139,0.2)}
.badge .dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.gauge-wrap{display:flex;justify-content:center;margin:20px 0}
.gauge{position:relative;width:180px;height:100px;overflow:visible}
.gauge svg{width:100%;height:100%}
.gauge-bg{fill:none;stroke:var(--border-s);stroke-width:12;stroke-linecap:round}
.gauge-fill{fill:none;stroke:url(#gaugeGrad);stroke-width:12;stroke-linecap:round;transition:stroke-dashoffset 1.4s cubic-bezier(.4,0,.2,1)}
.gauge-text{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;bottom:-8px}
.gauge-pct{font-size:32px;font-weight:800;background:linear-gradient(135deg,#6366f1,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.gauge-label{font-size:11px;color:var(--text3);margin-top:-2px}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:20px 0}
.stat{background:var(--border-s);border-radius:12px;padding:12px;text-align:center}
.stat-val{font-size:16px;font-weight:700;color:var(--text)}
.stat-lbl{font-size:11px;color:var(--text3);margin-top:2px}
.info-row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border-s);font-size:13px}
.info-row:last-child{border:none}
.info-label{color:var(--text3)}
.info-value{color:var(--text);font-weight:600;direction:ltr;text-align:left}
.section-title{font-size:14px;font-weight:700;margin:20px 0 12px;color:var(--text2)}
.sub-url{display:flex;align-items:center;gap:8px;background:var(--border-s);border-radius:12px;padding:10px 14px;margin-bottom:16px;cursor:pointer;transition:all .2s;border:1px solid transparent}
.sub-url:hover{border-color:var(--border)}
.sub-url span{flex:1;font-size:12px;color:var(--text2);direction:ltr;text-align:left;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sub-url .copy-btn{background:var(--accent-soft);color:var(--accent);border:none;border-radius:8px;padding:6px 10px;font-size:11px;font-weight:600;cursor:pointer;transition:all .2s;font-family:inherit}
.sub-url .copy-btn:hover{background:var(--accent);color:#fff}
.clients{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.client-btn{display:flex;align-items:center;justify-content:center;gap:6px;padding:10px 8px;border-radius:12px;border:1px solid var(--border-s);background:var(--border-s);color:var(--text);font-size:12px;font-weight:600;cursor:pointer;transition:all .2s;text-decoration:none;font-family:inherit}
.client-btn:hover{border-color:var(--accent);background:var(--accent-soft);color:var(--accent);transform:translateY(-1px);box-shadow:0 4px 12px rgba(99,102,241,0.15)}
.client-btn .c-icon{font-size:16px}
.theme-toggle{position:fixed;top:16px;left:16px;z-index:10;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:8px 10px;cursor:pointer;color:var(--text);font-size:16px;backdrop-filter:blur(12px);transition:all .2s}
.theme-toggle:hover{border-color:var(--accent)}
.countdown{font-size:13px;color:var(--text3);text-align:center;margin:8px 0}
.countdown span{color:var(--amber);font-weight:700}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(100px);background:var(--accent);color:#fff;padding:10px 24px;border-radius:12px;font-size:13px;font-weight:600;z-index:100;opacity:0;transition:all .3s ease;font-family:inherit}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1}
</style>
</head>
<body>
<div class="orbs"><div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div></div>
<button class="theme-toggle" onclick="toggleTheme()" id="themeBtn">&#9790;</button>
<div class="card">
  <div class="header">
    <div class="logo">U</div>
    <h1>__LABEL__</h1>
    <div class="sub">__DOMAIN__</div>
    <div id="badge"></div>
  </div>
  <div class="countdown" id="countdown" style="display:none"></div>
  <div class="gauge-wrap" id="gaugeWrap">
    <div class="gauge">
      <svg viewBox="0 0 200 110">
        <defs><linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" style="stop-color:#6366f1"/><stop offset="100%" style="stop-color:#06b6d4"/>
        </linearGradient></defs>
        <path class="gauge-bg" d="M 20 100 A 80 80 0 0 1 180 100"/>
        <path class="gauge-fill" id="gaugeFill" d="M 20 100 A 80 80 0 0 1 180 100"
              stroke-dasharray="251.3" stroke-dashoffset="251.3"/>
      </svg>
      <div class="gauge-text">
        <div class="gauge-pct" id="gaugePct">0%</div>
        <div class="gauge-label">مصرف حجم</div>
      </div>
    </div>
  </div>
  <div class="stats">
    <div class="stat"><div class="stat-val" id="sUsed">-</div><div class="stat-lbl">مصرف شده</div></div>
    <div class="stat"><div class="stat-val" id="sRemain">-</div><div class="stat-lbl">باقیمانده</div></div>
    <div class="stat"><div class="stat-val" id="sTotal">-</div><div class="stat-lbl">کل حجم</div></div>
    <div class="stat"><div class="stat-val" id="sConns">0</div><div class="stat-lbl">اتصال فعال</div></div>
  </div>
  <div class="section-title">لینک اشتراک</div>
  <div class="sub-url" onclick="copySub()">
    <span id="subUrlText">-</span>
    <button class="copy-btn">کپی</button>
  </div>
  <div class="section-title">نصب سریع</div>
  <div class="clients" id="clientBtns"></div>
</div>
<div class="toast" id="toast"></div>
<script>
const D=__DATA__;
document.title=D.label+' — Usf';
// Badge
const b=document.getElementById('badge');
if(!D.active){b.innerHTML='<span class="badge badge-disabled"><span class="dot"></span>غیرفعال</span>'}
else if(D.expired){b.innerHTML='<span class="badge badge-expired"><span class="dot"></span>منقضی</span>'}
else{b.innerHTML='<span class="badge badge-active"><span class="dot"></span>فعال</span>'}
// Gauge
const pct=D.usage_percent||0;
const circ=251.3;
setTimeout(()=>{document.getElementById('gaugeFill').style.strokeDashoffset=circ-(circ*Math.min(pct,100)/100);document.getElementById('gaugePct').textContent=Math.round(pct)+'%'},100);
// Stats
document.getElementById('sUsed').textContent=D.used_mb+' MB';
document.getElementById('sRemain').textContent=D.limit_bytes>0?D.remaining_mb+' MB':'نامحدود';
document.getElementById('sTotal').textContent=D.limit_bytes>0?D.limit_mb+' MB':'نامحدود';
document.getElementById('sConns').textContent=D.current_connections||0;
// Sub URL
document.getElementById('subUrlText').textContent=D.sub_url;
function copySub(){navigator.clipboard.writeText(D.sub_url);showToast('کپی شد!')}
// Client buttons
const clients=D.client_links||{};
const btns=document.getElementById('clientBtns');
const order=['V2RayN','V2RayNG','Streisand','Shadowrocket','Foxray','Nekoray','BS Client','Npv Tunnel','Hiddify','Mahsang'];
order.forEach(name=>{
  if(!clients[name])return;
  const a=document.createElement('a');
  a.className='client-btn';
  a.href=clients[name];
  a.target='_blank';
  a.rel='noopener';
  a.innerHTML='<span class="c-icon">&#128279;</span>'+name;
  btns.appendChild(a);
});
// Countdown
if(D.expiry&&D.expiry!==''){
  const cd=document.getElementById('countdown');
  cd.style.display='block';
  function updateCD(){
    const left=new Date(D.expiry)-Date.now();
    if(left<=0){cd.innerHTML='منقضی شده';return}
    const d=Math.floor(left/86400000),h=Math.floor((left%86400000)/3600000),m=Math.floor((left%3600000)/60000),s=Math.floor((left%60000)/1000);
    let t='';
    if(d>0)t+=d+' روز ';
    if(h>0)t+=h+' ساعت ';
    t+=m+' دقیقه '+s+' ثانیه';
    cd.innerHTML='مهلت باقیمانده: <span>'+t+'</span>';
  }
  updateCD();setInterval(updateCD,1000);
}
// Theme
function toggleTheme(){
  const t=document.documentElement.getAttribute('data-theme')==='light'?'dark':'light';
  document.documentElement.setAttribute('data-theme',t);
  localStorage.setItem('theme',t);
  document.getElementById('themeBtn').innerHTML=t==='dark'?'&#9790;':'&#9728;';
}
(function(){const s=localStorage.getItem('theme');if(s){document.documentElement.setAttribute('data-theme',s);document.getElementById('themeBtn').innerHTML=s==='dark'?'&#9790;':'&#9728;'}else if(window.matchMedia('(prefers-color-scheme:light)').matches){document.documentElement.setAttribute('data-theme','light');document.getElementById('themeBtn').innerHTML='&#9728;'}})();
// Toast
function showToast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2000)}
</script>
</body></html>'''

# ─── HTML: Login Page ────────────────────────────────────────────────────────
LOGIN_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta name="theme-color" content="#0b0f1a">
<title>Usf Panel — Login</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0b0f1a;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;font-family:'Inter',system-ui,sans-serif}
.orbs{position:fixed;inset:0;overflow:hidden;pointer-events:none}
.orb{position:absolute;border-radius:50%;filter:blur(120px);opacity:.15;animation:orb-f 20s ease-in-out infinite}
.o1{width:400px;height:400px;background:#6366f1;top:-100px;right:-80px}
.o2{width:300px;height:300px;background:#06b6d4;bottom:-80px;left:-60px;animation-delay:-7s}
@keyframes orb-f{0%,100%{transform:translate(0,0)}50%{transform:translate(30px,-20px)}}
.card{position:relative;z-index:1;background:rgba(15,23,42,0.6);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border:1px solid rgba(99,102,241,0.15);border-radius:20px;padding:40px 32px;max-width:380px;width:100%;box-shadow:0 25px 50px rgba(0,0,0,0.5)}
.logo{text-align:center;margin-bottom:32px}
.logo h1{font-size:28px;font-weight:800;background:linear-gradient(135deg,#6366f1,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:4px}
.logo p{color:#94a3b8;font-size:13px}
.form-group{margin-bottom:20px}
.form-group label{display:block;color:#cbd5e1;font-size:13px;font-weight:500;margin-bottom:6px}
.form-group input{width:100%;padding:12px 16px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:12px;color:#f1f5f9;font-size:14px;font-family:inherit;outline:none;transition:all .2s}
.form-group input:focus{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,0.15)}
.login-btn{width:100%;padding:12px;background:linear-gradient(135deg,#6366f1,#4f46e5);color:#fff;border:none;border-radius:12px;font-size:15px;font-weight:600;cursor:pointer;transition:all .2s;font-family:inherit}
.login-btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(99,102,241,0.3)}
.login-btn:active{transform:translateY(0)}
.login-btn:disabled{opacity:.5;cursor:not-allowed;transform:none}
.error{color:#ef4444;font-size:13px;text-align:center;margin-top:16px;min-height:20px}
</style>
</head>
<body>
<div class="orbs"><div class="orb o1"></div><div class="orb o2"></div></div>
<div class="card">
  <div class="logo"><h1>Usf Panel</h1><p>VLESS Tunnel Manager</p></div>
  <form id="loginForm" onsubmit="doLogin(event)">
    <div class="form-group"><label>Username</label><input type="text" id="username" autocomplete="username" required></div>
    <div class="form-group"><label>Password</label><input type="password" id="password" autocomplete="current-password" required></div>
    <button type="submit" class="login-btn" id="loginBtn">Sign In</button>
    <div class="error" id="error"></div>
  </form>
</div>
<script>
async function doLogin(e){
  e.preventDefault();
  const btn=document.getElementById('loginBtn');
  const err=document.getElementById('error');
  btn.disabled=true;err.textContent='';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:document.getElementById('username').value,password:document.getElementById('password').value})});
    const d=await r.json();
    if(r.ok){window.location.href='/dashboard'}
    else{err.textContent=d.detail||'Login failed';btn.disabled=false}
  }catch(x){err.textContent='Connection error';btn.disabled=false}
}
document.getElementById('username').focus();
</script>
</body></html>'''

# ─── PLACEHOLDER: Dashboard HTML will be appended below ──────────────────────
DASHBOARD_HTML = r'''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<meta name="theme-color" content="#0b0f1a">
<title>Usf Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
:root{
  --bg:#0b0f1a;--sidebar:#0f1629;--card:rgba(15,23,42,0.7);
  --glass:rgba(255,255,255,0.04);--border:rgba(255,255,255,0.07);
  --accent:#6366f1;--accent2:#818cf8;--cyan:#06b6d4;--emerald:#10b981;--amber:#f59e0b;--rose:#f43f5e;
  --text:#f1f5f9;--text2:#cbd5e1;--text3:#94a3b8;--text4:#64748b;
  --radius:14px;
}
html,body{height:100%;overflow:hidden}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.5;color:var(--text);background:var(--bg);display:flex}
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--text4);border-radius:3px}

.sidebar{width:230px;min-width:230px;background:var(--sidebar);border-left:1px solid var(--border);display:flex;flex-direction:column;overflow-y:auto;z-index:50;transition:transform .3s ease}
.logo{padding:18px 16px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border)}
.logo-icon{width:34px;height:34px;min-width:34px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--cyan));display:flex;align-items:center;justify-content:center;font-weight:800;font-size:15px;color:#fff}
.logo-text{font-size:15px;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;white-space:nowrap}
.nav{flex:1;padding:10px 8px}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:10px;color:var(--text3);cursor:pointer;transition:all .15s;margin-bottom:2px;font-size:13px;font-weight:500;white-space:nowrap;user-select:none}
.nav-item:hover{background:var(--glass);color:var(--text2)}
.nav-item.active{background:rgba(99,102,241,0.12);color:var(--accent2)}
.nav-item svg{width:18px;height:18px;min-width:18px;flex-shrink:0}
.sidebar-footer{padding:12px;border-top:1px solid var(--border);text-align:center;font-size:11px;color:var(--text4)}

.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:40}
.sidebar-overlay.show{display:block}

.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}
.topbar{height:54px;min-height:54px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 20px;gap:12px}
.topbar-left{display:flex;align-items:center;gap:10px;min-width:0}
.toggle-sidebar{display:none;background:none;border:none;color:var(--text3);cursor:pointer;padding:6px 8px;border-radius:8px;font-size:20px;line-height:1}
.toggle-sidebar:hover{color:var(--text);background:var(--glass)}
.page-title{font-size:15px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.topbar-right{display:flex;align-items:center;gap:10px;flex-shrink:0}
.topbar-badge{background:var(--glass);border:1px solid var(--border);border-radius:8px;padding:4px 10px;font-size:11px;color:var(--text3);white-space:nowrap;display:flex;align-items:center;gap:6px}
.status-dot{width:7px;height:7px;border-radius:50%;background:var(--emerald);animation:pdot 2s infinite}
@keyframes pdot{0%,100%{opacity:1}50%{opacity:.4}}
.logout-btn{background:none;border:1px solid var(--border);color:var(--text3);border-radius:8px;padding:5px 12px;font-size:12px;cursor:pointer;transition:all .15s;font-family:inherit;white-space:nowrap}
.logout-btn:hover{border-color:var(--rose);color:var(--rose)}

.content{flex:1;overflow-y:auto;padding:20px;-webkit-overflow-scrolling:touch}

.card{background:var(--card);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:var(--radius);padding:18px;transition:border-color .2s}
.card:hover{border-color:rgba(99,102,241,0.15)}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;gap:8px;flex-wrap:wrap}
.card-title{font-size:14px;font-weight:600;color:var(--text2)}

.stats-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}
.stat-card{position:relative;overflow:hidden}
.stat-icon{width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;margin-bottom:10px;font-size:17px}
.stat-value{font-size:22px;font-weight:800;margin-bottom:1px;line-height:1.2}
.stat-label{font-size:11px;color:var(--text3)}
.stat-bar{position:absolute;bottom:0;left:0;right:0;height:3px;background:var(--glass)}
.stat-bar-fill{height:100%;border-radius:0 2px 0 0;transition:width .6s}
.si{background:rgba(99,102,241,0.1);color:var(--accent)}
.sr{background:rgba(6,182,212,0.1);color:var(--cyan)}
.sd{background:rgba(245,158,11,0.1);color:var(--amber)}
.sn{background:rgba(16,185,129,0.1);color:var(--emerald)}
.sc{background:rgba(244,63,94,0.1);color:var(--rose)}
.sti{background:rgba(139,92,246,0.1);color:#8b5cf6}

.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}
.grid-3{display:grid;grid-template-columns:2fr 1fr;gap:14px;margin-bottom:20px}

.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;min-width:600px}
th{text-align:left;padding:9px 10px;font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:9px 10px;border-bottom:1px solid var(--glass);font-size:13px;vertical-align:middle}
tr:hover td{background:var(--glass)}
.st-active{color:var(--emerald);font-weight:600}
.st-expired{color:var(--rose);font-weight:600}
.st-disabled{color:var(--text4);font-weight:600}

.btn{display:inline-flex;align-items:center;gap:5px;padding:7px 14px;border-radius:10px;border:1px solid var(--border);background:var(--glass);color:var(--text);font-size:12px;font-weight:500;cursor:pointer;transition:all .15s;font-family:inherit;white-space:nowrap;user-select:none}
.btn:hover{border-color:var(--accent);color:var(--accent2)}
.btn:active{transform:scale(.97)}
.btn-p{background:linear-gradient(135deg,var(--accent),#4f46e5);border:none;color:#fff}
.btn-p:hover{color:#fff;box-shadow:0 4px 16px rgba(99,102,241,0.3)}
.btn-s{padding:4px 8px;font-size:11px;border-radius:7px}
.btn-d{border-color:rgba(244,63,94,0.3);color:var(--rose)}
.btn-d:hover{background:rgba(244,63,94,0.1);border-color:var(--rose)}
.btn-g{border-color:rgba(16,185,129,0.3);color:var(--emerald)}
.btn-g:hover{background:rgba(16,185,129,0.1);border-color:var(--emerald)}

.form-row{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px}
.form-group{margin-bottom:10px}
.form-group label{display:block;font-size:12px;font-weight:500;color:var(--text3);margin-bottom:4px}
.form-group input,.form-group select,.form-group textarea{width:100%;padding:8px 12px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:13px;font-family:inherit;outline:none;transition:border-color .15s}
.form-group input:focus,.form-group select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,0.1)}
.form-group textarea{resize:vertical;min-height:56px}
.form-group select{cursor:pointer}
.form-group select option{background:var(--sidebar);color:var(--text)}

.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);z-index:100;display:flex;align-items:center;justify-content:center;padding:16px;opacity:0;pointer-events:none;transition:opacity .2s}
.modal-overlay.open{opacity:1;pointer-events:auto}
.modal{background:var(--sidebar);border:1px solid var(--border);border-radius:16px;padding:22px;max-width:480px;width:100%;max-height:85vh;overflow-y:auto;transform:scale(.95);transition:transform .2s}
.modal-overlay.open .modal{transform:scale(1)}
.modal-title{font-size:16px;font-weight:700;margin-bottom:18px}

.toast-box{position:fixed;bottom:16px;right:16px;z-index:200;display:flex;flex-direction:column;gap:6px;pointer-events:none}
.toast{padding:10px 18px;border-radius:10px;font-size:13px;font-weight:500;animation:tin .25s ease;box-shadow:0 8px 24px rgba(0,0,0,0.3);pointer-events:auto}
.toast-ok{background:var(--emerald);color:#fff}
.toast-err{background:var(--rose);color:#fff}
.toast-info{background:var(--accent);color:#fff}
@keyframes tin{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}

.tag{display:inline-block;padding:2px 7px;border-radius:6px;font-size:10px;font-weight:600;background:rgba(99,102,241,0.1);color:var(--accent2);border:1px solid rgba(99,102,241,0.2)}

.cdrop{position:relative;display:inline-block}
.cmenu{position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:var(--sidebar);border:1px solid var(--border);border-radius:12px;padding:5px;min-width:150px;display:none;z-index:50;box-shadow:0 8px 24px rgba(0,0,0,0.5);margin-bottom:4px;max-height:260px;overflow-y:auto}
.cmenu.open{display:block}
.cmenu-i{display:block;width:100%;text-align:left;padding:7px 12px;border:none;background:none;color:var(--text);font-size:11px;cursor:pointer;border-radius:7px;transition:all .1s;font-family:inherit;white-space:nowrap}
.cmenu-i:hover{background:rgba(99,102,241,0.12);color:var(--accent2)}

.cl-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:10px}
.cl-item{display:flex;align-items:center;justify-content:space-between;gap:4px;padding:7px 10px;background:var(--glass);border-radius:8px;font-size:11px}
.cl-item span{color:var(--text2);font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cl-item button{background:none;border:none;color:var(--accent2);cursor:pointer;font-size:13px;padding:2px 4px;flex-shrink:0}

.log-e{padding:5px 8px;border-bottom:1px solid var(--glass);font-size:11px;font-family:'Courier New',monospace;display:flex;gap:8px}
.log-t{color:var(--text4);min-width:60px;flex-shrink:0}

.page{display:none}
.page.active{display:block}

.search{position:relative;margin-bottom:14px}
.search input{width:100%;padding:9px 14px 9px 36px;background:var(--glass);border:1px solid var(--border);border-radius:12px;color:var(--text);font-size:13px;outline:none;transition:border-color .15s;font-family:inherit}
.search input:focus{border-color:var(--accent)}
.search svg{position:absolute;right:12px;top:50%;transform:translateY(-50%);color:var(--text4);width:15px;height:15px}

.dep-res{background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.2);border-radius:12px;padding:14px;margin-top:14px}
.dep-res a{color:var(--emerald);text-decoration:none;font-weight:600;word-break:break-all}
.dep-res a:hover{text-decoration:underline}

.chart-c{position:relative;height:180px}

.empty{text-align:center;padding:40px 16px;color:var(--text4)}
.empty svg{width:44px;height:44px;margin:0 auto 10px;opacity:.3}

.info-r{display:flex;justify-content:space-between;padding:5px 0;font-size:13px}
.info-l{color:var(--text3)}
.info-v{color:var(--text);font-weight:600;direction:ltr}

.sub-box{display:flex;gap:6px;margin-top:10px;padding:8px;background:var(--glass);border-radius:8px}
.sub-box input{flex:1;min-width:0;padding:6px 10px;background:transparent;border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:11px;font-family:inherit;outline:none}

.inp{flex:1;padding:8px 12px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:13px;outline:none;font-family:inherit}

@media(max-width:900px){
  .stats-grid{grid-template-columns:repeat(2,1fr)}
  .grid-3{grid-template-columns:1fr}
}
@media(max-width:768px){
  .sidebar{position:fixed;right:0;top:0;bottom:0;z-index:50;transform:translateX(100%);width:260px;min-width:260px}
  .sidebar.open{transform:translateX(0)}
  .sidebar-overlay.show{display:block}
  .toggle-sidebar{display:block}
  .grid-2{grid-template-columns:1fr}
  .form-row{grid-template-columns:1fr}
  .content{padding:14px}
  .topbar{padding:0 14px}
  .cl-grid{grid-template-columns:1fr}
  table{min-width:500px}
}
@media(max-width:480px){
  .stats-grid{grid-template-columns:1fr 1fr}
  .stat-value{font-size:18px}
  .stat-icon{width:32px;height:32px;font-size:14px;margin-bottom:8px}
  .content{padding:12px}
  .card{padding:14px}
  .topbar-badge span:last-child{display:none}
}
</style>
</head>
<body>
<div class="sidebar-overlay" id="sbOverlay" onclick="closeSB()"></div>
<aside class="sidebar" id="sidebar">
  <div class="logo"><div class="logo-icon">U</div><div class="logo-text">Usf Panel</div></div>
  <nav class="nav" id="navMenu">
    <div class="nav-item active" data-page="dashboard" onclick="go('dashboard')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
      <span>Dashboard</span>
    </div>
    <div class="nav-item" data-page="inbounds" onclick="go('inbounds')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
      <span>Inbounds</span>
    </div>
    <div class="nav-item" data-page="ips" onclick="go('ips')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 4 10 15 15 0 0 1-4 10 15 15 0 0 1-4-10A15 15 0 0 1 12 2z"/></svg>
      <span>Clean IPs</span>
    </div>
    <div class="nav-item" data-page="domain" onclick="go('domain')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15 15 0 0 1 4 10 15 15 0 0 1-4 10 15 15 0 0 1-4-10A15 15 0 0 1 12 2z"/></svg>
      <span>Domain</span>
    </div>
    <div class="nav-item" data-page="builder" onclick="go('builder')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
      <span>Panel Builder</span>
    </div>
    <div class="nav-item" data-page="logs" onclick="go('logs')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14,2 14,8 20,8"/></svg>
      <span>Logs</span>
    </div>
    <div class="nav-item" data-page="settings" onclick="go('settings')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
      <span>Settings</span>
    </div>
  </nav>
  <div class="sidebar-footer">v__PANEL_VER__</div>
</aside>

<div class="main">
  <header class="topbar">
    <div class="topbar-left">
      <button class="toggle-sidebar" onclick="toggleSB()">&#9776;</button>
      <span class="page-title" id="pageTitle">Dashboard</span>
    </div>
    <div class="topbar-right">
      <span class="topbar-badge"><span class="status-dot"></span><span>Online</span></span>
      <button class="logout-btn" onclick="doLogout()">Logout</button>
    </div>
  </header>
  <div class="content">

    <div class="page active" id="page-dashboard">
      <div class="stats-grid">
        <div class="card stat-card"><div class="stat-icon si">&#9889;</div><div class="stat-value" id="xCpu">0%</div><div class="stat-label">CPU</div><div class="stat-bar"><div class="stat-bar-fill" id="xCpuB" style="width:0%;background:var(--accent)"></div></div></div>
        <div class="card stat-card"><div class="stat-icon sr">&#128190;</div><div class="stat-value" id="xRam">0%</div><div class="stat-label">RAM</div><div class="stat-bar"><div class="stat-bar-fill" id="xRamB" style="width:0%;background:var(--cyan)"></div></div></div>
        <div class="card stat-card"><div class="stat-icon sd">&#128451;</div><div class="stat-value" id="xDisk">0%</div><div class="stat-label">Disk</div><div class="stat-bar"><div class="stat-bar-fill" id="xDiskB" style="width:0%;background:var(--amber)"></div></div></div>
        <div class="card stat-card"><div class="stat-icon sn">&#128225;</div><div class="stat-value" id="xNet">0/0</div><div class="stat-label">Network</div><div class="stat-bar"><div class="stat-bar-fill" style="width:100%;background:var(--emerald)"></div></div></div>
        <div class="card stat-card"><div class="stat-icon sc">&#128279;</div><div class="stat-value" id="xConn">0</div><div class="stat-label">Connections</div><div class="stat-bar"><div class="stat-bar-fill" id="xConnB" style="width:0%;background:var(--rose)"></div></div></div>
        <div class="card stat-card"><div class="stat-icon sti">&#9200;</div><div class="stat-value" id="xUp">0m</div><div class="stat-label">Uptime</div><div class="stat-bar"><div class="stat-bar-fill" style="width:100%;background:#8b5cf6"></div></div></div>
      </div>
      <div class="grid-3">
        <div class="card"><div class="card-header"><span class="card-title">Traffic (24h)</span></div><div class="chart-c"><canvas id="tChart"></canvas></div></div>
        <div class="card">
          <div class="card-header"><span class="card-title">System Info</span></div>
          <div>
            <div class="info-r"><span class="info-l">RAM</span><span class="info-v" id="iRam">-</span></div>
            <div class="info-r"><span class="info-l">Swap</span><span class="info-v" id="iSwap">-</span></div>
            <div class="info-r"><span class="info-l">Storage</span><span class="info-v" id="iDisk">-</span></div>
            <div class="info-r"><span class="info-l">App RAM</span><span class="info-v" id="iApp">-</span></div>
            <div class="info-r"><span class="info-l">CPU Cores</span><span class="info-v" id="iCores">-</span></div>
            <div class="info-r"><span class="info-l">Total Traffic</span><span class="info-v" id="iTraff">-</span></div>
            <div class="info-r"><span class="info-l">Requests</span><span class="info-v" id="iReqs">-</span></div>
            <div class="info-r"><span class="info-l">IPv4</span><span class="info-v" id="iIP">-</span></div>
            <div class="info-r"><span class="info-l">Links</span><span class="info-v" id="iLinks">-</span></div>
          </div>
        </div>
      </div>
    </div>

    <div class="page" id="page-inbounds">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:8px">
        <div class="search" style="margin-bottom:0;flex:1;max-width:320px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
          <input type="text" id="sInb" placeholder="Search..." oninput="renderInb()">
        </div>
        <div style="display:flex;gap:6px;align-items:center">
          <select id="fStatus" style="padding:7px 10px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:12px;font-family:inherit;outline:none" onchange="renderInb()">
            <option value="all">All</option><option value="active">Active</option><option value="expired">Expired</option><option value="disabled">Disabled</option>
          </select>
          <button class="btn btn-p" onclick="openCreate()">+ New Link</button>
        </div>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Status</th><th>Usage</th><th>Expiry</th><th>Conn</th><th>Tag</th><th>Actions</th></tr></thead>
            <tbody id="inbBody"></tbody>
          </table>
        </div>
        <div class="empty" id="inbEmpty" style="display:none"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg><p>No inbounds yet.</p></div>
      </div>
    </div>

    <div class="page" id="page-ips">
      <div class="card">
        <div class="card-header"><span class="card-title">Clean IP Addresses</span></div>
        <p style="color:var(--text3);font-size:13px;margin-bottom:14px">Additional server addresses bundled in subscriptions.</p>
        <div style="display:flex;gap:8px;margin-bottom:14px">
          <input type="text" id="newAddr" placeholder="e.g. example.com or 1.2.3.4" class="inp">
          <button class="btn btn-p" onclick="addAddr()">Add</button>
        </div>
        <div id="addrList"></div>
      </div>
    </div>

    <div class="page" id="page-domain">
      <div class="card">
        <div class="card-header"><span class="card-title">Custom Domain</span></div>
        <p style="color:var(--text3);font-size:13px;margin-bottom:14px">Point your domain CNAME to your HF Space URL.</p>
        <div style="display:flex;gap:8px">
          <input type="text" id="domIn" placeholder="e.g. mypanel.example.com" class="inp">
          <button class="btn btn-p" onclick="saveDom()">Save</button>
        </div>
      </div>
    </div>

    <div class="page" id="page-builder">
      <div class="card" style="max-width:520px">
        <div class="card-header"><span class="card-title">Panel Builder</span></div>
        <p style="color:var(--text3);font-size:13px;margin-bottom:18px">Deploy a new Usf Panel to HuggingFace Spaces.</p>
        <div class="form-group"><label>HF Token</label><input type="password" id="pbTok" placeholder="hf_xxxxx"></div>
        <div class="form-row">
          <div class="form-group"><label>Space Name</label><input type="text" id="pbSp" placeholder="my-panel"></div>
          <div class="form-group"><label>Username</label><input type="text" id="pbUsr" value="admin"></div>
        </div>
        <div class="form-group"><label>Password</label><input type="password" id="pbPw" value="admin"></div>
        <button class="btn btn-p" style="width:100%;justify-content:center;padding:11px" onclick="deploy()" id="depBtn">Deploy Panel</button>
        <div class="dep-res" id="depRes" style="display:none"></div>
      </div>
    </div>

    <div class="page" id="page-logs">
      <div class="grid-2">
        <div class="card">
          <div class="card-header"><span class="card-title">Errors</span><button class="btn btn-s" onclick="loadLogs()">Refresh</button></div>
          <div id="errLogs" style="max-height:380px;overflow-y:auto"><p style="color:var(--text4);text-align:center;padding:16px">No errors</p></div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Connections</span></div>
          <div id="connHist" style="max-height:380px;overflow-y:auto"><p style="color:var(--text4);text-align:center;padding:16px">No connections</p></div>
        </div>
      </div>
    </div>

    <div class="page" id="page-settings">
      <div class="grid-2">
        <div class="card">
          <div class="card-header"><span class="card-title">Change Password</span></div>
          <div class="form-group"><label>Current</label><input type="password" id="curPw"></div>
          <div class="form-group"><label>New</label><input type="password" id="newPw"></div>
          <button class="btn btn-p" onclick="changePw()">Update</button>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Backup & Restore</span></div>
          <p style="color:var(--text3);font-size:13px;margin-bottom:14px">Export/import panel data.</p>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-g" onclick="dlBackup()">Download</button>
            <button class="btn" onclick="document.getElementById('restFile').click()">Restore</button>
            <input type="file" id="restFile" accept=".json" style="display:none" onchange="restBackup(this)">
          </div>
        </div>
      </div>
      <div class="card" style="margin-top:14px;max-width:520px">
        <div class="card-header"><span class="card-title">Service Control</span></div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-d" onclick="svcAct('stop')">Stop</button>
          <button class="btn btn-g" onclick="svcAct('restart')">Restart</button>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="modal-overlay" id="linkModal">
  <div class="modal">
    <div class="modal-title" id="mTitle">New Link</div>
    <input type="hidden" id="eUid">
    <div class="form-group"><label>Name *</label><input type="text" id="fLabel" placeholder="e.g. My VPN"></div>
    <div class="form-row">
      <div class="form-group"><label>Data Limit</label><div style="display:flex;gap:6px"><input type="number" id="fLimV" placeholder="0=unlimited" min="0" step="0.1" style="flex:1"><select id="fLimU" style="width:65px"><option>GB</option><option>MB</option></select></div></div>
      <div class="form-group"><label>Expiry (days)</label><input type="number" id="fExp" placeholder="0=never" min="0"></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>Max Conn</label><input type="number" id="fMC" placeholder="0=unlimited" min="0"></div>
      <div class="form-group"><label>Speed (Mbps)</label><input type="number" id="fSpd" placeholder="0=unlimited" min="0"></div>
    </div>
    <div class="form-group"><label>Tag</label><input type="text" id="fTag" placeholder="e.g. premium"></div>
    <div class="form-group"><label>Note</label><textarea id="fNote" placeholder="Optional..."></textarea></div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px">
      <button class="btn" onclick="closeM()">Cancel</button>
      <button class="btn btn-p" onclick="saveLink()" id="saveBtn">Create</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="clModal">
  <div class="modal">
    <div class="modal-title" id="clTitle">Client Links</div>
    <div id="clContent"></div>
    <div style="text-align:right;margin-top:14px"><button class="btn" onclick="closeCL()">Close</button></div>
  </div>
</div>

<div class="toast-box" id="toastBox"></div>

<script>
var PV='__PANEL_VER__';
var links=[];
var statsInt;
var tChart;

function api(u,o){
  o=o||{};
  return fetch(u,o).then(function(r){
    if(r.status===401){window.location.href='/login';return null}
    return r;
  }).catch(function(){toast('Connection error','err');return null});
}

function go(p){
  document.querySelectorAll('.page').forEach(function(el){el.classList.remove('active')});
  var pg=document.getElementById('page-'+p);
  if(pg)pg.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(function(el){el.classList.toggle('active',el.dataset.page===p)});
  var t={dashboard:'Dashboard',inbounds:'Inbounds',ips:'Clean IPs',domain:'Domain',builder:'Panel Builder',logs:'Logs',settings:'Settings'};
  document.getElementById('pageTitle').textContent=t[p]||p;
  if(p==='inbounds')loadLinks();
  if(p==='ips')loadAddrs();
  if(p==='domain')loadDom();
  if(p==='logs')loadLogs();
  closeSB();
}
function toggleSB(){document.getElementById('sidebar').classList.toggle('open');document.getElementById('sbOverlay').classList.toggle('show')}
function closeSB(){document.getElementById('sidebar').classList.remove('open');document.getElementById('sbOverlay').classList.remove('show')}

function toast(msg,type){
  var c=document.getElementById('toastBox');
  var d=document.createElement('div');
  d.className='toast toast-'+(type==='ok'?'ok':type==='err'?'err':'info');
  d.textContent=msg;c.appendChild(d);
  setTimeout(function(){if(d.parentNode)d.remove()},3000);
}

function loadStats(){
  api('/api/stats').then(function(r){if(!r)return;return r.json()}).then(function(s){
    if(!s)return;
    document.getElementById('xCpu').textContent=s.cpuUsage+'%';
    document.getElementById('xCpuB').style.width=Math.min(s.cpuUsage,100)+'%';
    document.getElementById('xRam').textContent=s.ramUsage+'%';
    document.getElementById('xRamB').style.width=Math.min(s.ramUsage,100)+'%';
    document.getElementById('xDisk').textContent=s.storageUsage+'%';
    document.getElementById('xDiskB').style.width=Math.min(s.storageUsage,100)+'%';
    document.getElementById('xNet').textContent=s.downloadSpeed.replace(/\/s$/,'')+' | '+s.uploadSpeed.replace(/\/s$/,'');
    document.getElementById('xConn').textContent=s.activeConnections;
    document.getElementById('xUp').textContent=s.uptime;
    document.getElementById('iRam').textContent=s.ramUsed+' / '+s.ramTotal;
    document.getElementById('iSwap').textContent=s.swapUsage+'%';
    document.getElementById('iDisk').textContent=s.storageUsed+' / '+s.storageTotal;
    document.getElementById('iApp').textContent=s.appRam;
    document.getElementById('iCores').textContent=s.cpuCores;
    document.getElementById('iTraff').textContent=s.totalTrafficMb+' MB';
    document.getElementById('iReqs').textContent=s.totalRequests;
    document.getElementById('iIP').textContent=s.ipv4;
    document.getElementById('iLinks').textContent=s.linksCount;
    updChart(s.hourlyTraffic);
  });
}

function initChart(){
  try{
    var ctx=document.getElementById('tChart');if(!ctx)return;
    var labels=[];var now=new Date();
    for(var i=23;i>=0;i--){var h=new Date(now-3600000*i);labels.push(('0'+h.getHours()).slice(-2)+':00')}
    tChart=new Chart(ctx,{type:'bar',data:{labels:labels,datasets:[{label:'Traffic',data:new Array(24).fill(0),backgroundColor:'rgba(99,102,241,0.3)',borderColor:'rgba(99,102,241,0.8)',borderWidth:1,borderRadius:4}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{color:'rgba(255,255,255,0.03)'},ticks:{color:'#64748b',font:{size:9},maxRotation:0}},y:{grid:{color:'rgba(255,255,255,0.03)'},ticks:{color:'#64748b',font:{size:9},callback:function(v){return v>=1048576?(v/1048576).toFixed(1)+'MB':v>=1024?(v/1024).toFixed(0)+'KB':v+'B'}}}}}});
  }catch(e){console.warn('Chart init:',e)}
}
function updChart(ht){
  if(!tChart)return;
  var now=new Date();var data=new Array(24).fill(0);
  for(var i=23;i>=0;i--){var h=new Date(now-3600000*i);var k=('0'+h.getHours()).slice(-2)+':00';data[23-i]=ht[k]||0}
  tChart.data.datasets[0].data=data;tChart.update('none');
}

function loadLinks(){
  api('/api/links').then(function(r){if(!r)return;return r.json()}).then(function(d){
    if(!d)return;links=d.links;renderInb();
  });
}

function esc(s){if(!s)return '';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}

function renderInb(){
  var q=(document.getElementById('sInb').value||'').toLowerCase();
  var fs=document.getElementById('fStatus').value;
  var fl=links.filter(function(l){
    if(q&&l.label.toLowerCase().indexOf(q)===-1&&!(l.tag||'').toLowerCase().indexOf(q)===-1)return false;
    if(fs==='active'&&(!l.active||l.expired))return false;
    if(fs==='expired'&&!l.expired)return false;
    if(fs==='disabled'&&l.active)return false;
    return true;
  });
  var tb=document.getElementById('inbBody');
  var em=document.getElementById('inbEmpty');
  if(!fl.length){tb.innerHTML='';em.style.display='block';return}
  em.style.display='none';
  tb.innerHTML=fl.map(function(l){
    var pct=l.limit_bytes>0?Math.round(l.used_bytes/l.limit_bytes*100):0;
    var sc=l.expired?'st-expired':l.active?'st-active':'st-disabled';
    var st=l.expired?'Expired':l.active?'Active':'Disabled';
    var uMB=l.used_bytes>=1073741824?(l.used_bytes/1073741824).toFixed(2)+' GB':(l.used_bytes/1048576).toFixed(1)+' MB';
    var lT=l.limit_bytes>0?(l.limit_bytes>=1073741824?(l.limit_bytes/1073741824).toFixed(1)+' GB':(l.limit_bytes/1048576).toFixed(0)+' MB'):'Unlimited';
    var eT=l.expiry?new Date(l.expiry).toLocaleDateString():'Never';
    var tg=l.tag?'<span class="tag">'+esc(l.tag)+'</span>':'-';
    var cl=l.client_links||{};
    var cmKeys=Object.keys(cl);
    var cmHTML='';
    if(cmKeys.length){
      cmHTML='<div class="cdrop"><button class="btn btn-s" onclick="toggleCM(event)" title="Copy">&#128203;</button><div class="cmenu" id="cm_'+l.uuid+'">';
      cmKeys.forEach(function(k){cmHTML+='<button class="cmenu-i" data-link="'+esc(cl[k])+'" data-name="'+esc(k)+'" onclick="copyFromMenu(this)">'+esc(k)+'</button>';});
      cmHTML+='</div></div>';
    }
    return '<tr><td><strong>'+esc(l.label)+'</strong></td><td><span class="'+sc+'">'+st+'</span></td><td style="font-size:12px">'+uMB+' / '+lT+' ('+pct+'%)</td><td style="font-size:12px">'+eT+'</td><td>'+l.current_connections+'</td><td>'+tg+'</td><td style="white-space:nowrap"><button class="btn btn-s" onclick="showCL(\''+l.uuid+'\')">&#128279;</button> '+cmHTML+' <button class="btn btn-s" onclick="openEdit(\''+l.uuid+'\')">&#9998;</button> <button class="btn btn-s btn-d" onclick="delLink(\''+l.uuid+'\',\''+esc(l.label)+'\')">&#10005;</button></td></tr>';
  }).join('');
}

function toggleCM(e){e.stopPropagation();var m=e.target.nextElementSibling;document.querySelectorAll('.cmenu.open').forEach(function(el){if(el!==m)el.classList.remove('open')});m.classList.toggle('open')}
document.addEventListener('click',function(){document.querySelectorAll('.cmenu.open').forEach(function(el){el.classList.remove('open')})});

function copyFromMenu(btn){
  var link=btn.getAttribute('data-link');
  var name=btn.getAttribute('data-name');
  copyTxt(link,name);
}

function showCL(uid){
  var l=null;for(var i=0;i<links.length;i++){if(links[i].uuid===uid){l=links[i];break}}
  if(!l)return;
  document.getElementById('clTitle').textContent='Client Links \u2014 '+l.label;
  var cl=l.client_links||{};
  var keys=Object.keys(cl);
  var html='<div class="cl-grid">';
  keys.forEach(function(k){
    html+='<div class="cl-item"><span title="'+esc(cl[k])+'">'+esc(k)+'</span><button data-link="'+esc(cl[k])+'" data-name="'+esc(k)+'" onclick="copyFromMenu(this)">&#128203;</button></div>';
  });
  html+='</div>';
  html+='<div style="margin-top:10px"><div style="font-size:11px;color:var(--text3);margin-bottom:4px">Subscription URL</div><div class="sub-box"><input type="text" value="'+esc(l.sub_url)+'" readonly id="subUrlIn"><button class="btn btn-s" onclick="copyTxt(document.getElementById(\'subUrlIn\').value,\'Subscription\')">Copy</button></div></div>';
  document.getElementById('clContent').innerHTML=html;
  document.getElementById('clModal').classList.add('open');
}
function closeCL(){document.getElementById('clModal').classList.remove('open')}

function openCreate(){
  document.getElementById('mTitle').textContent='New Link';
  document.getElementById('eUid').value='';
  document.getElementById('fLabel').value='';
  document.getElementById('fLimV').value='';
  document.getElementById('fExp').value='';
  document.getElementById('fMC').value='';
  document.getElementById('fSpd').value='';
  document.getElementById('fTag').value='';
  document.getElementById('fNote').value='';
  document.getElementById('saveBtn').textContent='Create';
  document.getElementById('linkModal').classList.add('open');
}

function openEdit(uid){
  var l=null;for(var i=0;i<links.length;i++){if(links[i].uuid===uid){l=links[i];break}}
  if(!l)return;
  document.getElementById('mTitle').textContent='Edit \u2014 '+l.label;
  document.getElementById('eUid').value=uid;
  document.getElementById('fLabel').value=l.label;
  if(l.limit_bytes>0){var gb=l.limit_bytes/1073741824;if(gb>=1){document.getElementById('fLimV').value=gb;document.getElementById('fLimU').value='GB'}else{document.getElementById('fLimV').value=l.limit_bytes/1048576;document.getElementById('fLimU').value='MB'}}
  else{document.getElementById('fLimV').value='';document.getElementById('fLimU').value='GB'}
  if(l.expiry){var diff=Math.max(0,Math.round((new Date(l.expiry)-Date.now())/86400000));document.getElementById('fExp').value=diff||''}else{document.getElementById('fExp').value=''}
  document.getElementById('fMC').value=l.max_connections||'';
  document.getElementById('fSpd').value=l.speed_limit||'';
  document.getElementById('fTag').value=l.tag||'';
  document.getElementById('fNote').value=l.note||'';
  document.getElementById('saveBtn').textContent='Save';
  document.getElementById('linkModal').classList.add('open');
}

function closeM(){document.getElementById('linkModal').classList.remove('open')}

function saveLink(){
  var uid=document.getElementById('eUid').value;
  var body={label:document.getElementById('fLabel').value,limit_value:parseFloat(document.getElementById('fLimV').value)||0,limit_unit:document.getElementById('fLimU').value,expiry_days:parseFloat(document.getElementById('fExp').value)||0,max_connections:parseInt(document.getElementById('fMC').value)||0,speed_limit:parseInt(document.getElementById('fSpd').value)||0,tag:document.getElementById('fTag').value,note:document.getElementById('fNote').value};
  var url=uid?'/api/links/'+uid:'/api/links';
  var method=uid?'PATCH':'POST';
  api(url,{method:method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){
    if(!r){toast('Error','err');return}
    if(r.ok){toast(uid?'Updated':'Created','ok');closeM();loadLinks()}
    else r.json().then(function(d){toast(d.detail||'Error','err')});
  });
}

function delLink(uid,label){
  if(!confirm('Delete "'+label+'"?'))return;
  api('/api/links/'+uid,{method:'DELETE'}).then(function(r){
    if(r&&r.ok){toast('Deleted','ok');loadLinks()}else toast('Error','err');
  });
}

function loadAddrs(){
  api('/api/addresses').then(function(r){if(!r)return;return r.json()}).then(function(d){
    if(!d)return;
    var el=document.getElementById('addrList');
    if(d.addresses.length){el.innerHTML=d.addresses.map(function(a,i){return '<div style="display:flex;align-items:center;justify-content:space-between;padding:9px 12px;border:1px solid var(--glass);border-radius:10px;margin-bottom:5px"><span style="font-size:13px;direction:ltr">'+esc(a)+'</span><button class="btn btn-s btn-d" onclick="delAddr('+i+')">Remove</button></div>'}).join('')}
    else{el.innerHTML='<p style="color:var(--text4);text-align:center;padding:14px">No custom IPs</p>'}
  });
}
function addAddr(){
  var a=document.getElementById('newAddr').value.trim();if(!a)return;
  api('/api/addresses',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:a})}).then(function(r){
    if(r&&r.ok){document.getElementById('newAddr').value='';loadAddrs();toast('Added','ok')}
    else if(r) r.json().then(function(d){toast(d.detail||'Error','err')});
  });
}
function delAddr(i){api('/api/addresses/'+i,{method:'DELETE'}).then(function(r){if(r&&r.ok){loadAddrs();toast('Removed','ok')}})}

function loadDom(){
  api('/api/domain').then(function(r){if(!r)return;return r.json()}).then(function(d){if(d)document.getElementById('domIn').value=d.domain||''});
}
function saveDom(){
  var d=document.getElementById('domIn').value.trim();
  api('/api/domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:d})}).then(function(r){if(r&&r.ok)toast('Saved','ok');else toast('Error','err')});
}

function deploy(){
  var tk=document.getElementById('pbTok').value.trim();
  var sp=document.getElementById('pbSp').value.trim();
  var us=document.getElementById('pbUsr').value.trim();
  var pw=document.getElementById('pbPw').value;
  if(!tk||!sp){toast('Token and Space name required','err');return}
  var btn=document.getElementById('depBtn');btn.disabled=true;btn.textContent='Deploying...';
  api('/api/panel-builder/deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hf_token:tk,space_name:sp,admin_username:us,admin_password:pw})}).then(function(r){
    btn.disabled=false;btn.textContent='Deploy Panel';
    if(r&&r.ok){return r.json()}else if(r){return r.json().then(function(d){toast(d.detail||'Deploy failed','err');return null})}
  }).then(function(d){
    if(!d)return;
    document.getElementById('depRes').style.display='block';
    document.getElementById('depRes').innerHTML='<strong style="color:var(--emerald)">Deployed!</strong><br><br><a href="'+d.space_url+'" target="_blank">'+d.space_url+'</a><br><a href="'+d.app_url+'" target="_blank">'+d.app_url+'</a>';
    toast('Deployed!','ok');
  });
}

function loadLogs(){
  api('/api/logs').then(function(r){if(!r)return;return r.json()}).then(function(d){
    if(!d)return;
    var el=document.getElementById('errLogs');
    el.innerHTML=d.errors.length?d.errors.map(function(e){return '<div class="log-e"><span class="log-t">'+(e.time?e.time.slice(11,19):'')+'</span><span style="color:var(--rose);font-weight:600">ERR</span><span>'+esc(e.error||'')+'</span></div>'}).join(''):'<p style="color:var(--text4);text-align:center;padding:16px">No errors</p>';
    var ch=document.getElementById('connHist');
    ch.innerHTML=d.history.length?d.history.map(function(h){return '<div class="log-e"><span class="log-t">'+(h.time?h.time.slice(11,19):'')+'</span><span style="color:var(--text3)">'+esc(h.label||'')+'</span><span>'+esc(h.ip||'')+'</span><span style="color:var(--text4)">'+esc(h.target||'')+'</span></div>'}).join(''):'<p style="color:var(--text4);text-align:center;padding:16px">No connections</p>';
  });
}

function changePw(){
  var c=document.getElementById('curPw').value;var n=document.getElementById('newPw').value;
  if(!c||!n){toast('Fill both fields','err');return}
  api('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:c,new_password:n})}).then(function(r){
    if(r&&r.ok){toast('Changed','ok');document.getElementById('curPw').value='';document.getElementById('newPw').value=''}
    else if(r) r.json().then(function(d){toast(d.detail||'Error','err')});
  });
}
function dlBackup(){
  api('/api/backup').then(function(r){if(!r)return;return r.blob()}).then(function(blob){
    if(!blob)return;var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='usf-backup.json';a.click();toast('Downloaded','ok');
  });
}
function restBackup(inp){
  var file=inp.files[0];if(!file)return;
  file.text().then(function(text){
    api('/api/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:text}).then(function(r){
      if(r&&r.ok){toast('Restored!','ok');loadLinks()}else if(r) r.json().then(function(d){toast(d.detail||'Error','err')});
    });
  });inp.value='';
}
function svcAct(a){
  if(!confirm(a==='stop'?'Stop service?':'Restart service?'))return;
  api('/api/service/'+a,{method:'POST'}).then(function(r){if(r&&r.ok)toast('Done','ok');else toast('Error','err')});
}
function doLogout(){api('/api/logout',{method:'POST'}).then(function(){window.location.href='/login'})}

function copyTxt(text,name){
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(function(){toast(name+' copied','ok')}).catch(function(){fbCopy(text,name)})}
  else fbCopy(text,name);
}
function fbCopy(text,name){
  var ta=document.createElement('textarea');ta.value=text;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();
  try{document.execCommand('copy');toast(name+' copied','ok')}catch(e){toast('Copy failed','err')}
  ta.remove();
}

initChart();
loadStats();
statsInt=setInterval(loadStats,3000);
</script>
</body></html>'''

# ─── HTML Route Handlers ────────────────────────────────────────────────────
@app.get("/status/{uid}")
async def status_page(uid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            return HTMLResponse(content=STATUS_404, status_code=404)
        domain = CUSTOM_DOMAIN or get_domain()
        client_links = generate_all_client_links(uid, link["label"])
        data_json = json.dumps({
            "label": link["label"], "domain": domain, "uuid": uid,
            "active": link["active"], "expired": is_expired(link),
            "expiry": link.get("expiry", ""),
            "used_bytes": link["used_bytes"], "limit_bytes": link["limit_bytes"],
            "used_mb": round(link["used_bytes"] / 1048576, 2),
            "limit_mb": round(link["limit_bytes"] / 1048576, 2) if link["limit_bytes"] > 0 else 0,
            "remaining_mb": round((link["limit_bytes"] - link["used_bytes"]) / 1048576, 2) if link["limit_bytes"] > 0 else 0,
            "usage_percent": round((link["used_bytes"] / link["limit_bytes"]) * 100, 1) if link["limit_bytes"] > 0 else 0,
            "sub_url": f"https://{domain}/sub/{uid}",
            "client_links": client_links,
            "speed_limit": link.get("speed_limit", 0),
            "current_connections": count_connections_for_link(uid),
        }, ensure_ascii=False)
    html = STATUS_HTML.replace("__TITLE__", link["label"] + " — Usf")
    html = html.replace("__LABEL__", link["label"])
    html = html.replace("__DOMAIN__", domain)
    html = html.replace("__DATA__", data_json)
    return HTMLResponse(content=html)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/login")
    html = DASHBOARD_HTML.replace("__PANEL_VER__", PANEL_VERSION)
    return HTMLResponse(content=html)

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=CONFIG["port"], log_level="info", access_log=False)
