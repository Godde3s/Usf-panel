#  USF Panel v2.0.0 — Backend Core
#  (Imports through WebSocket Tunnel)
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
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from html import escape as _hesc

# ─── Speed optimizations (uvloop + orjson + httptools) ─────────────────────
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    _HAS_UVLOOP = True
except ImportError:
    _HAS_UVLOOP = False

try:
    import orjson
    _HAS_ORJSON = True
except ImportError:
    orjson = None
    _HAS_ORJSON = False

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Usf-Gateway")
logger.info(f"Usf v2.0.0 starting | uvloop={_HAS_UVLOOP} | orjson={_HAS_ORJSON}")

app = FastAPI(title="Usf", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 7860)),
    "secret": os.environ.get("SECRET_KEY", "Usf-default-secret-key"),
}

PANEL_VERSION = os.environ.get("PANEL_VERSION", "v2.0.0")
CORE_VERSION = os.environ.get("CORE_VERSION", "v26.4.25")
TELEGRAM_HANDLE = os.environ.get("TELEGRAM_HANDLE", "@Usf")

SERVICE_RUNNING = True
SERVICE_STARTED_AT = time.time()

# ─── SQLite persistence (survives HF Space restarts) ─────────────────────────
DB_PATH = os.environ.get("DB_PATH", "/tmp/usf.db")
_DB_LOCK = threading.Lock()

def db_init():
    try:
        with _DB_LOCK, sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS kv (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.commit()
        logger.info(f"SQLite initialized at {DB_PATH}")
    except Exception as e:
        logger.warning(f"SQLite init failed: {e} (running in-memory only)")

def db_set(key: str, value: str):
    try:
        with _DB_LOCK, sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO kv (key, value, updated_at) VALUES (?, ?, ?)",
                (key, value, datetime.now().isoformat())
            )
            conn.commit()
    except Exception as e:
        logger.warning(f"db_set({key}) failed: {e}")

def db_get(key: str, default=None):
    try:
        with _DB_LOCK, sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
            return row[0] if row else default
    except Exception:
        return default

def db_delete(key: str):
    try:
        with _DB_LOCK, sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM kv WHERE key=?", (key,))
            conn.commit()
    except Exception:
        pass

# ─── Rate limiting ────────────────────────────────────────────────────────────
RATE_LIMIT = defaultdict(lambda: deque(maxlen=20))
RATE_LIMIT_LOCK = asyncio.Lock()

async def rate_limit_check(ip: str, max_requests: int = 10, window_sec: int = 60) -> bool:
    now = time.time()
    async with RATE_LIMIT_LOCK:
        dq = RATE_LIMIT[ip]
        while dq and now - dq[0] > window_sec:
            dq.popleft()
        if len(dq) >= max_requests:
            return False
        dq.append(now)
        return True

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Anti-fingerprinting middleware ──────────────────────────────────────────
@app.middleware("http")
async def sanitize_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    for h in ("server", "x-powered-by", "via", "x-aspnet-version", "x-forwarded-host"):
        if h in response.headers:
            del response.headers[h]
    response.headers["server"] = "Usf"
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["x-frame-options"] = "SAMEORIGIN"
    response.headers["referrer-policy"] = "no-referrer"
    response.headers["x-xss-protection"] = "1; mode=block"
    if request.url.scheme == "https":
        response.headers["strict-transport-security"] = "max-age=31536000; includeSubDomains"
    return response

# ─── State ───────────────────────────────────────────────────────────────────
connections: dict = {}
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=100)
hourly_traffic: dict = defaultdict(int)
connection_history: deque = deque(maxlen=500)
http_client: httpx.AsyncClient | None = None

_net_baseline = {"bytes_sent": 0, "bytes_recv": 0, "ts": time.time()}

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

CUSTOM_ADDRESSES: list = ["amazonaws.com"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

CUSTOM_DOMAIN: str = ""
CUSTOM_DOMAIN_LOCK = asyncio.Lock()

SESSION_COOKIE = "Usf_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {
    "password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin")),
    "username": os.environ.get("ADMIN_USERNAME", "admin"),
}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
                logger.info("Keep-alive ping sent")
        except Exception:
            pass

async def periodic_save():
    while True:
        await asyncio.sleep(30)
        try:
            async with LINKS_LOCK:
                links_snapshot = json.dumps(LINKS, ensure_ascii=False)
            db_set("links", links_snapshot)
            async with CUSTOM_ADDRESSES_LOCK:
                addrs_snapshot = json.dumps(CUSTOM_ADDRESSES)
            db_set("addresses", addrs_snapshot)
            async with CUSTOM_DOMAIN_LOCK:
                db_set("domain", CUSTOM_DOMAIN)
            db_set("auth_hash", AUTH["password_hash"])
        except Exception as e:
            logger.warning(f"periodic_save failed: {e}")

@app.on_event("startup")
async def startup():
    global http_client, _net_baseline, CUSTOM_DOMAIN, CUSTOM_ADDRESSES, AUTH
    db_init()
    saved_links = db_get("links")
    if saved_links:
        try:
            parsed = json.loads(saved_links)
            async with LINKS_LOCK:
                LINKS.update(parsed)
            logger.info(f"Loaded {len(parsed)} links from SQLite")
        except Exception as e:
            logger.warning(f"Failed to load links: {e}")
    saved_addrs = db_get("addresses")
    if saved_addrs:
        try:
            async with CUSTOM_ADDRESSES_LOCK:
                CUSTOM_ADDRESSES = json.loads(saved_addrs)
        except Exception:
            pass
    saved_domain = db_get("domain")
    if saved_domain is not None:
        CUSTOM_DOMAIN = saved_domain
    saved_pw = db_get("auth_hash")
    if saved_pw:
        AUTH["password_hash"] = saved_pw

    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)

    try:
        nc = psutil.net_io_counters()
        _net_baseline = {"bytes_sent": nc.bytes_sent, "bytes_recv": nc.bytes_recv, "ts": time.time()}
    except Exception:
        _net_baseline = {"bytes_sent": 0, "bytes_recv": 0, "ts": time.time()}

    logger.info(f"Usf v2.0.0 started on port {CONFIG['port']}")
    asyncio.create_task(keep_alive())
    asyncio.create_task(periodic_save())

@app.on_event("shutdown")
async def shutdown():
    try:
        async with LINKS_LOCK:
            links_snapshot = json.dumps(LINKS, ensure_ascii=False)
        db_set("links", links_snapshot)
        async with CUSTOM_ADDRESSES_LOCK:
            db_set("addresses", json.dumps(CUSTOM_ADDRESSES))
        async with CUSTOM_DOMAIN_LOCK:
            db_set("domain", CUSTOM_DOMAIN)
        db_set("auth_hash", AUTH["password_hash"])
        logger.info("State saved before shutdown")
    except Exception as e:
        logger.warning(f"Shutdown save failed: {e}")
    if http_client:
        await http_client.aclose()

# ─── Helper Functions ────────────────────────────────────────────────────────

def get_domain() -> str:
    return os.environ.get("SPACE_HOST", "localhost").replace("https://", "").replace("http://", "")

def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(uuid.uuid4())
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "Usf", address: str = None) -> str:
    domain = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()
    addr = address if address else domain
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "h2,http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

def uptime_seconds() -> int:
    return int(time.time() - stats["start_time"])

def uptime() -> str:
    secs = uptime_seconds()
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def os_uptime_str() -> str:
    try:
        secs = int(time.time() - psutil.boot_time())
        d = secs // 86400
        h = (secs % 86400) // 3600
        m = (secs % 3600) // 60
        if d > 0:
            return f"{d}d {h}h {m}m"
        elif h > 0:
            return f"{h}h {m}m"
        else:
            return f"{m}m"
    except Exception:
        return "N/A"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

def compute_expiry(expiry_days) -> str:
    try:
        days = float(expiry_days or 0)
    except (TypeError, ValueError):
        days = 0
    if days <= 0:
        return ""
    return (datetime.now() + timedelta(days=days)).isoformat()

def is_expired(link) -> bool:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return False
    try:
        return datetime.now() >= datetime.fromisoformat(exp)
    except (TypeError, ValueError):
        return False

def expiry_epoch(link) -> int:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return 0
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
                "active": True, "expiry": "", "speed_limit": 0, "tag": "",
                "note": ""
            }

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

def count_connections_for_link(uid: str) -> int:
    return len(link_ip_map.get(uid, set()))

def remove_ip_from_link(uid: str, ip: str):
    if uid in link_ip_map:
        link_ip_map[uid].discard(ip)
        if not link_ip_map[uid]:
            link_ip_map.pop(uid, None)

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    link_ip_map.pop(uid, None)

def get_real_ips():
    ipv4 = ""
    ipv6 = ""
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    ipv4 = addr.address
                elif addr.family == socket.AF_INET6 and not addr.address.startswith("::1") and not addr.address.startswith("fe80"):
                    ipv6 = addr.address.split("%")[0]
    except Exception:
        pass
    return ipv4, ipv6

def get_net_speed():
    global _net_baseline
    try:
        nc = psutil.net_io_counters()
        now = time.time()
        elapsed = now - _net_baseline["ts"]
        if elapsed < 0.1:
            elapsed = 1.0
        up_bps = (nc.bytes_sent - _net_baseline["bytes_sent"]) / elapsed
        down_bps = (nc.bytes_recv - _net_baseline["bytes_recv"]) / elapsed
        _net_baseline = {"bytes_sent": nc.bytes_sent, "bytes_recv": nc.bytes_recv, "ts": now}
        return nc.bytes_sent, nc.bytes_recv, up_bps, down_bps
    except Exception:
        return 0, 0, 0, 0

def fmt_bytes_speed(bps: float) -> str:
    if bps >= 1_048_576:
        return f"{bps/1_048_576:.2f} MB"
    elif bps >= 1024:
        return f"{bps/1024:.2f} KB"
    else:
        return f"{bps:.0f} B"

def fmt_bytes(b: int) -> str:
    if b >= 1_073_741_824:
        return f"{b/1_073_741_824:.2f} GB"
    elif b >= 1_048_576:
        return f"{b/1_048_576:.2f} MB"
    elif b >= 1024:
        return f"{b/1024:.1f} KB"
    return f"{b} B"

def get_net_connections_count():
    try:
        conns = psutil.net_connections()
        tcp = sum(1 for c in conns if c.type == socket.SOCK_STREAM)
        udp = sum(1 for c in conns if c.type == socket.SOCK_DGRAM)
        return tcp, udp
    except Exception:
        return 0, 0

#  USF Panel v2.0.0 — API Endpoints
# ============================================================

# ─── Main Endpoints ───────────────────────────────────────────────────────────

@app.get("/")
async def root(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return RedirectResponse(url="/login")

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or request.client.host if request.client else "unknown"
    if not await rate_limit_check(client_ip, max_requests=5, window_sec=60):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again in a minute.")
    body = await request.json()
    password = str(body.get("password") or "")
    username = str(body.get("username") or "")
    if username and username != AUTH["username"]:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/", secure=True)
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(hourly_traffic),
    }

@app.get("/api/stats")
async def get_api_stats(_=Depends(require_auth)):
    cpu = psutil.cpu_percent(interval=0.1)
    vm = psutil.virtual_memory()
    ram_pct = vm.percent
    ram_used_mb = vm.used / 1_048_576
    ram_total_mb = vm.total / 1_048_576

    load_avg = [0.0, 0.0, 0.0]
    try:
        load_avg = list(os.getloadavg())
    except Exception:
        pass

    total_sent_bytes, total_recv_bytes, up_bps, down_bps = get_net_speed()
    ipv4, ipv6 = get_real_ips()
    tcp, udp = get_net_connections_count()

    try:
        proc = psutil.Process()
        threads = proc.num_threads()
        proc_ram = proc.memory_info().rss / 1_048_576
    except Exception:
        threads = 0
        proc_ram = ram_used_mb

    try:
        sw = psutil.swap_memory()
        swap_pct = sw.percent
        swap_used = sw.used
        swap_total = sw.total
    except Exception:
        swap_pct, swap_used, swap_total = 0.0, 0, 0

    try:
        du = psutil.disk_usage("/")
        disk_pct = du.percent
        disk_used = du.used
        disk_total = du.total
    except Exception:
        disk_pct, disk_used, disk_total = 0.0, 0, 0

    try:
        cpu_cores = psutil.cpu_count(logical=True) or 1
    except Exception:
        cpu_cores = 1

    if SERVICE_RUNNING:
        xray_uptime_s = int(time.time() - SERVICE_STARTED_AT)
        if xray_uptime_s < 3600:
            xray_uptime = f"{xray_uptime_s // 60}m"
        elif xray_uptime_s < 86400:
            xray_uptime = f"{xray_uptime_s // 3600}h {(xray_uptime_s % 3600)//60}m"
        else:
            xray_uptime = f"{xray_uptime_s // 86400}d {(xray_uptime_s % 86400)//3600}h"
    else:
        xray_uptime = "Stopped"

    return {
        "cpuUsage": round(cpu, 1),
        "ramUsage": round(ram_pct, 1),
        "ramUsed": f"{ram_used_mb:.1f} MB",
        "ramTotal": f"{ram_total_mb:.0f} MB",
        "uptime": os_uptime_str(),
        "xrayUptime": xray_uptime,
        "systemLoad": f"{load_avg[0]:.2f} | {load_avg[1]:.2f} | {load_avg[2]:.2f}",
        "threads": threads,
        "uploadSpeed": fmt_bytes_speed(up_bps) + "/s",
        "downloadSpeed": fmt_bytes_speed(down_bps) + "/s",
        "totalSent": fmt_bytes(total_sent_bytes),
        "totalReceived": fmt_bytes(total_recv_bytes),
        "ipv4": ipv4 or "N/A",
        "ipv6": ipv6 or "N/A",
        "tcpConnections": tcp,
        "udpConnections": udp,
        "activeConnections": len(connections),
        "totalTrafficMb": round(stats["total_bytes"] / 1_048_576, 2),
        "totalRequests": stats["total_requests"],
        "linksCount": len(LINKS),
        "domain": get_domain(),
        "hourlyTraffic": dict(hourly_traffic),
        "recentErrors": list(error_logs)[-5:],
        "cpuCores": cpu_cores,
        "swapUsage": round(swap_pct, 1),
        "swapUsed": fmt_bytes(swap_used),
        "swapTotal": fmt_bytes(swap_total),
        "storageUsage": round(disk_pct, 1),
        "storageUsed": fmt_bytes(disk_used),
        "storageTotal": fmt_bytes(disk_total),
        "appRam": f"{proc_ram:.2f} MB",
        "xrayRunning": SERVICE_RUNNING,
        "panelVersion": PANEL_VERSION,
        "coreVersion": CORE_VERSION,
        "telegram": TELEGRAM_HANDLE,
    }

async def _stop_service_internal():
    global SERVICE_RUNNING
    SERVICE_RUNNING = False
    for cid, ws in list(connection_sockets.items()):
        try:
            await ws.close(code=1012, reason="service stopped")
        except Exception:
            pass
    connections.clear()
    connection_sockets.clear()
    link_ip_map.clear()

@app.get("/api/service")
async def service_status(_=Depends(require_auth)):
    return {"running": SERVICE_RUNNING, "core_version": CORE_VERSION,
            "active_connections": len(connections)}

@app.post("/api/service/stop")
async def service_stop(_=Depends(require_auth)):
    await _stop_service_internal()
    logger.info("Core stopped via panel")
    return {"ok": True, "running": SERVICE_RUNNING}

@app.post("/api/service/restart")
async def service_restart(_=Depends(require_auth)):
    global SERVICE_RUNNING, SERVICE_STARTED_AT
    await _stop_service_internal()
    await asyncio.sleep(0.3)
    SERVICE_RUNNING = True
    SERVICE_STARTED_AT = time.time()
    logger.info("Core restarted via panel")
    return {"ok": True, "running": SERVICE_RUNNING}

@app.get("/api/logs")
async def get_logs(_=Depends(require_auth)):
    return {
        "running": SERVICE_RUNNING,
        "totals": {
            "bytes": stats["total_bytes"],
            "requests": stats["total_requests"],
            "errors": stats["total_errors"],
        },
        "errors": list(error_logs)[-50:],
        "connections": [
            {"id": cid, "uuid": info.get("uuid"), "ip": info.get("ip"),
             "connected_at": info.get("connected_at"), "bytes": info.get("bytes", 0)}
            for cid, info in connections.items()
        ],
        "history": list(connection_history)[-50:],
    }

@app.get("/api/config")
async def get_runtime_config(_=Depends(require_auth)):
    async with LINKS_LOCK:
        inbounds = [{"uuid": uid, "remark": d["label"], "enabled": d["active"],
                     "ws_path": f"/ws/{uid}"} for uid, d in LINKS.items()]
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    return {
        "panel": "Usf",
        "panel_version": PANEL_VERSION,
        "core_version": CORE_VERSION,
        "running": SERVICE_RUNNING,
        "port": CONFIG["port"],
        "domain": CUSTOM_DOMAIN or get_domain(),
        "protocol": "vless",
        "network": "ws",
        "security": "tls",
        "clean_addresses": addresses,
        "inbounds": inbounds,
    }

@app.get("/api/backup")
async def download_backup(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links_copy = {uid: dict(d) for uid, d in LINKS.items()}
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    backup = {
        "panel": "Usf",
        "panel_version": PANEL_VERSION,
        "core_version": CORE_VERSION,
        "exported_at": datetime.now().isoformat(),
        "domain": CUSTOM_DOMAIN,
        "addresses": addresses,
        "username": AUTH["username"],
        "password_hash": AUTH["password_hash"],
        "links": links_copy,
    }
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
        raise HTTPException(status_code=400, detail="Invalid backup file")
    async with LINKS_LOCK:
        LINKS.clear()
        for uid, d in links.items():
            if not isinstance(d, dict):
                continue
            LINKS[uid] = {
                "label": str(d.get("label", "Restored"))[:60],
                "limit_bytes": int(d.get("limit_bytes", 0) or 0),
                "used_bytes": int(d.get("used_bytes", 0) or 0),
                "max_connections": int(d.get("max_connections", 0) or 0),
                "created_at": d.get("created_at", datetime.now().isoformat()),
                "active": bool(d.get("active", True)),
                "expiry": d.get("expiry", ""),
                "speed_limit": int(d.get("speed_limit", 0) or 0),
                "tag": str(d.get("tag", "")),
                "note": str(d.get("note", "")),
            }
    if isinstance(body.get("addresses"), list):
        async with CUSTOM_ADDRESSES_LOCK:
            CUSTOM_ADDRESSES.clear()
            for a in body["addresses"]:
                if isinstance(a, str) and a:
                    CUSTOM_ADDRESSES.append(a)
    if isinstance(body.get("domain"), str):
        async with CUSTOM_DOMAIN_LOCK:
            CUSTOM_DOMAIN = body["domain"]
    return {"ok": True, "restored": len(LINKS)}

# ─── Links/Inbounds CRUD ─────────────────────────────────────────────────────

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Name must contain only English letters, numbers, and: - _ . space")
    if not label:
        raise HTTPException(status_code=400, detail="Name is required")
    async with LINKS_LOCK:
        if any(d["label"].lower() == label.lower() for d in LINKS.values()):
            raise HTTPException(status_code=400, detail="A link with this name already exists")
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    if max_conn < 0:
        max_conn = 0
    expiry = compute_expiry(body.get("expiry_days"))
    speed_limit = int(body.get("speed_limit") or 0)
    tag = str(body.get("tag") or "")[:30]
    note = str(body.get("note") or "")[:200]
    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
            "max_connections": max_conn, "created_at": datetime.now().isoformat(),
            "active": True, "expiry": expiry, "speed_limit": speed_limit,
            "tag": tag, "note": note,
        }
    return {
        "uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "active": True, "expiry": expiry,
        "created_at": LINKS[uid]["created_at"],
        "vless_link": generate_vless_link(uid, remark=f"{label}"),
        "speed_limit": speed_limit, "tag": tag,
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({
                "uuid": uid, "label": data["label"], "limit_bytes": data["limit_bytes"],
                "used_bytes": data["used_bytes"], "max_connections": data.get("max_connections", 0),
                "active": data["active"], "expiry": data.get("expiry", ""),
                "expired": is_expired(data), "created_at": data["created_at"],
                "current_connections": count_connections_for_link(uid),
                "vless_link": generate_vless_link(uid, remark=f"{data['label']}"),
                "speed_limit": data.get("speed_limit", 0),
                "tag": data.get("tag", ""),
                "note": data.get("note", ""),
            })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.get("/api/inbounds")
async def list_inbounds(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({
                "id": uid, "uuid": uid, "remark": data["label"], "label": data["label"],
                "protocol": "vless", "enabled": data["active"], "active": data["active"],
                "limit_bytes": data["limit_bytes"], "used_bytes": data["used_bytes"],
                "total_flow": data["limit_bytes"] / 1_073_741_824 if data["limit_bytes"] > 0 else 0,
                "max_connections": data.get("max_connections", 0),
                "expiry": data.get("expiry", ""), "expired": is_expired(data),
                "created_at": data["created_at"],
                "current_connections": count_connections_for_link(uid),
                "vless_link": generate_vless_link(uid, remark=f"{data['label']}"),
                "clients": [{"id": uid, "email": data["label"]}],
                "speed_limit": data.get("speed_limit", 0),
                "tag": data.get("tag", ""),
                "note": data.get("note", ""),
            })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"items": result, "total": len(result)}

@app.patch("/api/inbounds/{uid}")
async def patch_inbound(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="inbound not found")
        if "enabled" in body:
            LINKS[uid]["active"] = bool(body["enabled"])
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            lu = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "expiry_days" in body:
            LINKS[uid]["expiry"] = compute_expiry(body.get("expiry_days"))
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
        if "remark" in body:
            LINKS[uid]["label"] = str(body["remark"])[:60]
        if "max_connections" in body:
            mc = int(body["max_connections"] or 0)
            LINKS[uid]["max_connections"] = mc if mc >= 0 else 0
        if "speed_limit" in body:
            LINKS[uid]["speed_limit"] = int(body["speed_limit"] or 0)
        if "tag" in body:
            LINKS[uid]["tag"] = str(body.get("tag", ""))[:30]
        if "note" in body:
            LINKS[uid]["note"] = str(body.get("note", ""))[:200]
    return {"ok": True}

@app.delete("/api/inbounds/{uid}")
async def delete_inbound(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "expiry_days" in body:
            LINKS[uid]["expiry"] = compute_expiry(body.get("expiry_days"))
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
        if "max_connections" in body:
            mc = int(body["max_connections"] or 0)
            LINKS[uid]["max_connections"] = mc if mc >= 0 else 0
        if "speed_limit" in body:
            LINKS[uid]["speed_limit"] = int(body["speed_limit"] or 0)
        if "tag" in body:
            LINKS[uid]["tag"] = str(body.get("tag", ""))[:30]
        if "note" in body:
            LINKS[uid]["note"] = str(body.get("note", ""))[:200]
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

# ─── Domain & Addresses ──────────────────────────────────────────────────────

@app.get("/api/domain")
async def get_custom_domain(_=Depends(require_auth)):
    async with CUSTOM_DOMAIN_LOCK:
        return {"domain": CUSTOM_DOMAIN}

@app.post("/api/domain")
async def set_custom_domain(request: Request, _=Depends(require_auth)):
    body = await request.json()
    domain = (body.get("domain") or "").strip().lower()
    if domain:
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
        if not re.match(r'^[a-z0-9\-_.]+$', domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
    async with CUSTOM_DOMAIN_LOCK:
        global CUSTOM_DOMAIN
        CUSTOM_DOMAIN = domain
    return {"ok": True, "domain": CUSTOM_DOMAIN}

@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    address = (body.get("address") or "").strip()
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', address):
        raise HTTPException(status_code=400, detail="Invalid address format")
    async with CUSTOM_ADDRESSES_LOCK:
        if address in CUSTOM_ADDRESSES:
            raise HTTPException(status_code=400, detail="Address already exists")
        CUSTOM_ADDRESSES.append(address)
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            CUSTOM_ADDRESSES.pop(index)
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

# ─── Subscription ─────────────────────────────────────────────────────────────

@app.get("/api/links/{uid}/sub")
async def get_subscription(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    vless_link = generate_vless_link(uid, remark=f"{link['label']}")
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    used_mb = round(used / (1024 * 1024), 2)
    limit_mb = round(limit / (1024 * 1024), 2) if limit > 0 else 0
    pct = round((used / limit) * 100, 1) if limit > 0 else 0
    remaining_mb = round((limit - used) / (1024 * 1024), 2) if limit > 0 else 0
    sub_content = f"vless://{uid}@{get_domain()}:443?encryption=none&security=tls&type=ws&host={get_domain()}&path=/ws/{uid}&sni={get_domain()}&fp=chrome&alpn=h2,http/1.1#{link['label']}"
    encoded = base64.b64encode(sub_content.encode()).decode()
    return {
        "subscription_url": f"https://{get_domain()}/sub/{uid}",
        "config": vless_link,
        "label": link["label"],
        "used_bytes": used, "limit_bytes": limit,
        "used_mb": used_mb, "limit_mb": limit_mb,
        "remaining_mb": remaining_mb, "usage_percent": pct,
        "active": link["active"],
        "sub_base64": encoded, "sub_text": sub_content,
    }

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    if not link["active"]:
        raise HTTPException(status_code=403, detail="link disabled")
    if is_expired(link):
        raise HTTPException(status_code=403, detail="link expired")
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    sub_links = []
    server_link = generate_vless_link(uid, remark=f"{link['label']}-Server")
    sub_links.append(server_link)
    for i, addr in enumerate(addresses):
        remark = f"{link['label']}-IP{i+1}"
        vless_link = generate_vless_link(uid, remark=remark, address=addr)
        sub_links.append(vless_link)
    sub_content = "\n".join(sub_links)
    encoded = base64.b64encode(sub_content.encode()).decode()
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=\"sub.txt\"",
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={link['limit_bytes']}; expire={expiry_epoch(link)}",
        "profile-title": f"{link['label']}",
    }
    return Response(content=encoded, headers=headers)

# ─── Panel Builder API ────────────────────────────────────────────────────────

@app.post("/api/panel-builder/deploy")
async def panel_builder_deploy(request: Request, _=Depends(require_auth)):
    """Deploy a new USF panel to the user's HuggingFace Space."""
    try:
        from huggingface_hub import HfApi, SpaceHardware
    except ImportError:
        raise HTTPException(status_code=500, detail="huggingface_hub not installed on this Space")

    body = await request.json()
    hf_token = (body.get("hf_token") or "").strip()
    space_name = (body.get("space_name") or "").strip().lower()
    admin_user = (body.get("admin_username") or "admin").strip()[:30]
    admin_pass = (body.get("admin_password") or "admin").strip()
    secret_key = secrets.token_urlsafe(32)

    if not hf_token:
        raise HTTPException(status_code=400, detail="HuggingFace token is required")
    if not space_name or not re.match(r'^[a-z0-9][a-z0-9\-_.]{0,98}[a-z0-9]$', space_name):
        raise HTTPException(status_code=400, detail="Invalid space name (lowercase, alphanumeric, hyphens)")
    if len(admin_pass) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    try:
        api = HfApi(token=hf_token)
        repo_id = f"{api.whoami()['name']}/{space_name}"

        # Read current app.py as template
        import inspect
        caller_file = inspect.getfile(lambda: None)
        with open(caller_file, 'r', encoding='utf-8') as f:
            app_code = f.read()

        dockerfile = """FROM python:3.11-slim
RUN pip install --no-cache-dir fastapi uvicorn httpx psutil httptools uvloop orjson huggingface_hub
COPY app.py .
EXPOSE 7860
CMD ["python", "app.py"]
"""
        readme = f"""---
title: "{space_name}"
sdk: docker
app_port: 7860
---
"""
        api.create_repo(repo_id=repo_id, repo_type="space", exist_ok=True, space_sdk="docker")
        api.upload_file(
            path_or_fileobj=app_code.encode('utf-8'),
            path_in_repo="app.py",
            repo_id=repo_id,
            repo_type="space",
        )
        api.upload_file(
            path_or_fileobj=dockerfile.encode('utf-8'),
            path_in_repo="Dockerfile",
            repo_id=repo_id,
            repo_type="space",
        )
        api.upload_file(
            path_or_fileobj=readme.encode('utf-8'),
            path_in_repo="README.md",
            repo_id=repo_id,
            repo_type="space",
        )

        return {
            "ok": True,
            "space_url": f"https://huggingface.co/spaces/{repo_id}",
            "app_url": f"https://{repo_id.split('/')[1]}.hf.space",
            "repo_id": repo_id,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

#  USF Panel v2.0.0 — WebSocket Tunnel (unchanged core)
# ============================================================

RELAY_BUF = 512 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: return False
        if not link["active"]: return False
        if is_expired(link): return False
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            writer.write(data); await writer.drain()
    except WebSocketDisconnect: pass
    finally:
        try: writer.write_eof()
        except: pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except: pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        if not SERVICE_RUNNING:
            await websocket.close(code=1012, reason="service stopped"); return
        async with LINKS_LOCK:
            link_data = LINKS.get(uuid)
            if link_data is None or not link_data["active"]:
                await websocket.close(code=1008, reason="link not found or disabled"); return
            if is_expired(link_data):
                await websocket.close(code=1008, reason="link expired"); return
            max_conn = link_data.get("max_connections", 0)
        if max_conn > 0:
            already_connected = client_ip in link_ip_map.get(uuid, set())
            if not already_connected:
                current = count_connections_for_link(uuid)
                if current >= max_conn:
                    await websocket.close(code=1008, reason="connection limit reached"); return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        link_ip_map[uuid].add(client_ip)

        # Connection history
        async with LINKS_LOCK:
            link_label = LINKS.get(uuid, {}).get("label", "?")
        connection_history.append({
            "time": datetime.now().isoformat(), "uuid": uuid[:8],
            "label": link_label, "ip": client_ip, "target": f"{address}:{port}",
        })

        size = len(first_chunk)
        stats["total_bytes"] += size; stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now().strftime("%H:00")] += size
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        try:
            sock = writer.get_extra_info('socket')
            if sock is not None:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512 * 1024)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512 * 1024)
                except Exception:
                    pass
        except Exception:
            pass
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%H:00")] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload); await writer.drain()
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                uid = info.get("uuid")
                ip = info.get("ip")
                if uid and ip:
                    has_other = any(c.get("uuid") == uid and c.get("ip") == ip for c in connections.values())
                    if not has_other:
                        remove_ip_from_link(uid, ip)

#  USF Panel v2.0.0 — Status Page Function
# ============================================================

STATUS_404_HTML = r'''<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>لینک نامعتبر</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e1a;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;font-family:system-ui,-apple-system,sans-serif}
.box{background:rgba(20,27,45,0.7);backdrop-filter:blur(24px);border:1px solid rgba(99,102,241,0.15);
border-radius:24px;padding:48px 36px;text-align:center;max-width:400px;width:100%;
box-shadow:0 25px 50px -12px rgba(0,0,0,0.6)}
.icon{width:56px;height:56px;border-radius:50%;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.2);
display:flex;align-items:center;justify-content:center;margin:0 auto 16px}
.icon svg{width:24px;height:24px;stroke:#ef4444;fill:none;stroke-width:2}
h1{color:#f1f5f9;font-size:18px;margin-bottom:8px;font-weight:700}
p{color:#94a3b8;font-size:13px;line-height:1.7}
</style></head><body>
<div class="box">
<div class="icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg></div>
<h1>لینک نامعتبر است</h1>
<p>این اشتراک وجود ندارد یا حذف شده است.</p>
</div></body></html>'''

STATUS_HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,viewport-fit=cover">
<meta name="theme-color" content="#0b0f1a" id="meta-theme">
<title>__TITLE__</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
:root{--bg:#0b0f1a;--card:rgba(15,23,42,0.6);--glass:rgba(255,255,255,0.04);--accent:#6366f1;--accent2:#818cf8;
--accent-soft:rgba(99,102,241,0.12);--accent-glow:rgba(99,102,241,0.3);--text:#f1f5f9;--text2:#cbd5e1;
--text3:#94a3b8;--text4:#64748b;--border:rgba(99,102,241,0.18);--border-s:rgba(255,255,255,0.06);
--green:#22c55e;--red:#ef4444;--amber:#f59e0b;--radius:16px}
html[data-theme="light"]{--bg:#f1f5f9;--card:rgba(255,255,255,0.8);--glass:rgba(0,0,0,0.03);
--text:#0f172a;--text2:#334155;--text3:#64748b;--text4:#94a3b8;--border:rgba(99,102,241,0.25);--border-s:rgba(0,0,0,0.06)}
html,body{height:100%}
body{font-family:'Vazirmatn',system-ui,-apple-system,sans-serif;background:var(--bg);
background-image:radial-gradient(ellipse 80% 50% at 50% -20%,rgba(99,102,241,0.12),transparent 60%),radial-gradient(ellipse 60% 40% at 80% 100%,rgba(139,92,246,0.08),transparent 50%);
background-attachment:fixed;min-height:100vh;min-height:100dvh;display:flex;justify-content:center;align-items:center;
padding:20px;color:var(--text);line-height:1.6;-webkit-font-smoothing:antialiased}
.card{background:var(--card);backdrop-filter:blur(32px) saturate(180%);-webkit-backdrop-filter:blur(32px) saturate(180%);
max-width:480px;width:100%;padding:28px 24px;border-radius:24px;border:1px solid var(--border);
box-shadow:0 30px 60px -15px rgba(0,0,0,0.5),0 0 0 1px rgba(255,255,255,0.03) inset;
position:relative;overflow:hidden;animation:cardIn .6s cubic-bezier(.16,1,.3,1)}
@keyframes cardIn{from{opacity:0;transform:translateY(20px) scale(.97)}to{opacity:1;transform:none}}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
background:linear-gradient(90deg,transparent,var(--accent) 30%,#a78bfa 50%,var(--accent) 70%,transparent);opacity:.6;pointer-events:none}
.theme-btn{position:absolute;top:14px;left:14px;width:34px;height:34px;border-radius:50%;background:var(--glass);
border:1px solid var(--border-s);color:var(--text3);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .25s;z-index:2}
.theme-btn:hover{background:var(--accent-soft);color:var(--accent)}
.theme-btn svg{width:16px;height:16px}
.theme-btn .sun{display:none}
html[data-theme="light"] .theme-btn .sun{display:block}
html[data-theme="light"] .theme-btn .moon{display:none}
.header{text-align:center;margin-bottom:20px;position:relative;z-index:1}
.logo-text{font-size:28px;font-weight:800;letter-spacing:-.02em;background:linear-gradient(135deg,var(--text),var(--accent2));
-webkit-background-clip:text;background-clip:text;color:transparent}
.label-chip{display:inline-flex;align-items:center;gap:6px;margin-top:8px;padding:5px 14px;background:var(--glass);
border:1px solid var(--border);border-radius:999px;font-size:12px;color:var(--text2);max-width:90%;word-break:break-word}
.status-banner{display:flex;align-items:center;justify-content:center;gap:8px;padding:10px 16px;border-radius:var(--radius);
margin-bottom:18px;font-size:13px;font-weight:600;__STATUS_STYLE__}
.status-dot{width:8px;height:8px;border-radius:50%;__DOT_STYLE__;animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.8)}}
.sub-section{margin:16px 0;padding:16px;background:linear-gradient(135deg,var(--accent-soft),rgba(99,102,241,0.02));
border:1px solid var(--border);border-radius:var(--radius);position:relative;z-index:1}
.sec-label{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--text3);margin-bottom:8px;
font-weight:700;display:flex;align-items:center;gap:6px}
.sec-dot{width:5px;height:5px;border-radius:50%;background:var(--accent);box-shadow:0 0 8px var(--accent);animation:pulse 2.5s ease-in-out infinite}
.sub-row{display:flex;align-items:stretch;gap:8px}
.sub-link{flex:1;min-width:0;font-family:ui-monospace,monospace;font-size:11px;color:var(--accent);text-decoration:none;
background:rgba(0,0,0,0.3);padding:10px 12px;border-radius:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
direction:ltr;transition:all .2s;border:1px solid rgba(99,102,241,0.12);display:flex;align-items:center;gap:6px}
html[data-theme="light"] .sub-link{background:rgba(0,0,0,0.04)}
.sub-link:hover{background:var(--accent-soft);border-color:rgba(99,102,241,0.35)}
.btn{border:none;font-family:inherit;font-weight:600;border-radius:10px;cursor:pointer;transition:all .2s;
display:inline-flex;align-items:center;justify-content:center;gap:6px;font-size:12px;padding:10px 14px;white-space:nowrap}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent2);transform:translateY(-1px);box-shadow:0 8px 20px var(--accent-glow)}
.client-grid{margin-top:12px;display:grid;grid-template-columns:repeat(3,1fr);gap:6px}
.client-chip{display:flex;flex-direction:column;align-items:center;gap:3px;padding:8px 4px;border-radius:10px;
text-decoration:none;background:var(--glass);border:1px solid var(--border-s);transition:all .2s;
font-size:9.5px;color:var(--text3);font-weight:600}
.client-chip:hover{background:var(--accent-soft);border-color:var(--border);color:var(--accent);transform:translateY(-1px)}
.ci{width:24px;height:24px;border-radius:6px;display:flex;align-items:center;justify-content:center;
font-size:10px;font-weight:800;color:#fff;letter-spacing:-.02em}
.ci-v2n{background:#5b8def}.ci-v2g{background:#22c55e}.ci-str{background:#ff6b6b}
.ci-sr{background:#1e293b}.ci-fox{background:#f97316}.ci-bull{background:#8b5cf6}
.ci-npv{background:#06b6d4}.ci-hid{background:#ec4899}.ci-mah{background:#14b8a6}
.gauge-section{margin:20px 0;display:flex;flex-direction:column;align-items:center;position:relative;z-index:1}
.gauge-wrap{position:relative;width:140px;height:140px;margin-bottom:6px}
.gauge-svg{width:100%;height:100%;transform:rotate(-90deg)}
.gauge-track{fill:none;stroke:rgba(255,255,255,0.05);stroke-width:8}
html[data-theme="light"] .gauge-track{stroke:rgba(0,0,0,0.06)}
.gauge-fill{fill:none;stroke:url(#gGrad);stroke-width:8;stroke-linecap:round;stroke-dasharray:377;stroke-dashoffset:377;
transition:stroke-dashoffset 1.2s cubic-bezier(.16,1,.3,1);filter:drop-shadow(0 0 6px var(--accent-glow))}
.gauge-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge-pct{font-size:28px;font-weight:800;color:var(--text);letter-spacing:-.02em;line-height:1}
.gauge-pct .pct-s{font-size:16px;color:var(--text3);font-weight:600;margin-left:1px}
.gauge-lbl{font-size:10px;color:var(--text3);margin-top:2px;font-weight:600;text-transform:uppercase;letter-spacing:.06em}
.gauge-stats{display:flex;gap:16px;margin-top:6px;flex-wrap:wrap;justify-content:center}
.gs{text-align:center}
.gs .gv{font-family:ui-monospace,monospace;font-size:12px;font-weight:700;color:var(--text);direction:ltr}
.gs .gl{font-size:9px;color:var(--text3);margin-top:1px;text-transform:uppercase;letter-spacing:.05em}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:16px 0;position:relative;z-index:1}
.info-card{background:var(--glass);border:1px solid var(--border-s);border-radius:12px;padding:11px 12px;transition:all .2s}
.info-card:hover{background:var(--accent-soft);border-color:var(--border)}
.info-lbl{font-size:9px;text-transform:uppercase;letter-spacing:.06em;color:var(--text3);margin-bottom:3px;font-weight:700}
.info-val{font-size:13px;color:var(--text);font-weight:700;direction:ltr;unicode-bidi:embed}
.info-val.sm{font-size:11px}
.config-sec{margin-top:14px;position:relative;z-index:1}
.config-box{background:rgba(0,0,0,0.35);border:1px solid var(--border-s);border-radius:10px;padding:10px 12px;
font-family:ui-monospace,monospace;font-size:10.5px;color:var(--text2);word-break:break-all;direction:ltr;
text-align:left;max-height:72px;overflow-y:auto;line-height:1.5}
html[data-theme="light"] .config-box{background:rgba(0,0,0,0.03)}
.config-box::-webkit-scrollbar{width:4px}
.config-box::-webkit-scrollbar-thumb{background:rgba(99,102,241,0.3);border-radius:2px}
.btn-row{display:flex;gap:6px;margin-top:6px}
.btn-row .btn{flex:1}
.btn-ghost{background:var(--glass);color:var(--text2);border:1px solid var(--border-s)}
.btn-ghost:hover{border-color:var(--border);color:var(--text)}
.footer{text-align:center;font-size:10px;color:var(--text4);margin-top:18px;padding-top:14px;
border-top:1px solid var(--border-s);display:flex;align-items:center;justify-content:center;gap:10px;flex-wrap:wrap;position:relative;z-index:1}
.badge{background:var(--accent-soft);color:var(--accent);padding:3px 10px;border-radius:999px;font-size:10px;font-weight:700}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(100px);
background:rgba(15,23,42,0.95);backdrop-filter:blur(16px);color:#fff;padding:11px 20px;border-radius:999px;
font-size:12px;font-weight:500;border:1px solid var(--border);box-shadow:0 14px 36px rgba(0,0,0,0.5);
opacity:0;transition:all .4s cubic-bezier(.4,0,.2,1);z-index:1000;pointer-events:none;max-width:90vw}
html[data-theme="light"] .toast{background:rgba(15,23,42,0.92)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.countdown{font-family:ui-monospace,monospace;font-weight:700;color:var(--text);direction:ltr}
@media(max-width:560px){body{padding:0;align-items:flex-start}
.card{border-radius:0;min-height:100vh;min-height:100dvh;padding:24px 16px;padding-top:max(24px,env(safe-area-inset-top));padding-bottom:max(24px,env(safe-area-inset-bottom))}
.info-grid{grid-template-columns:1fr 1fr;gap:6px}.sub-row{flex-direction:column}.sub-link{width:100%}
.logo-text{font-size:24px}.gauge-wrap{width:120px;height:120px}.gauge-pct{font-size:24px}}
@media(max-width:380px){.info-grid{grid-template-columns:1fr}.client-grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="card">
  <button class="theme-btn" onclick="toggleTheme()">
    <svg class="moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
    <svg class="sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
  </button>
  <div class="header">
    <div class="logo-text">Usf</div>
    <div class="label-chip">__LABEL__</div>
  </div>
  <div class="status-banner">
    <span class="status-dot"></span>
    __STATUS_TEXT__
  </div>
  <div class="sub-section">
    <div class="sec-label"><span class="sec-dot"></span>لینک اشتراک</div>
    <div class="sub-row">
      <a href="__SUB_URL__" class="sub-link" target="_blank" title="__SUB_URL__">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        <span>__SUB_URL__</span>
      </a>
      <button class="btn btn-primary" onclick="copySub()">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        کپی
      </button>
    </div>
    <div class="client-grid">
      <a class="client-chip" href="v2rayn://install-sub?url=__SUB_URL_ENC__"><span class="ci ci-v2n">N</span><span>V2RayN</span></a>
      <a class="client-chip" href="v2rayng://install-sub?url=__SUB_URL_ENC__"><span class="ci ci-v2g">G</span><span>V2RayNG</span></a>
      <a class="client-chip" href="streisand://import/__SUB_URL_ENC__"><span class="ci ci-str">S</span><span>Streisand</span></a>
      <a class="client-chip" href="shadowrocket://add/sub://__SUB_URL_B64__"><span class="ci ci-sr">SR</span><span>Shadowrocket</span></a>
      <a class="client-chip" href="foxray://install-sub?url=__SUB_URL_ENC__"><span class="ci ci-fox">F</span><span>Foxray</span></a>
      <a class="client-chip" href="npv://install-sub?url=__SUB_URL_ENC__"><span class="ci ci-npv">N</span><span>Npv</span></a>
      <a class="client-chip" href="hiddify://import/__SUB_URL_ENC__"><span class="ci ci-hid">H</span><span>Hiddify</span></a>
      <a class="client-chip" href="mahsa://import/__SUB_URL_ENC__"><span class="ci ci-mah">M</span><span>Mahsang</span></a>
      <a class="client-chip" href="bullshit://install/__SUB_URL_ENC__"><span class="ci ci-bull">B</span><span>BS Client</span></a>
    </div>
  </div>
  <div class="gauge-section">
    <div class="gauge-wrap">
      <svg class="gauge-svg" viewBox="0 0 140 140">
        <defs><linearGradient id="gGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#22c55e"/><stop offset="50%" stop-color="#6366f1"/><stop offset="100%" stop-color="#ef4444"/>
        </linearGradient></defs>
        <circle class="gauge-track" cx="70" cy="70" r="60"/>
        <circle class="gauge-fill" id="gf" cx="70" cy="70" r="60"/>
      </svg>
      <div class="gauge-center">
        <div class="gauge-pct"><span id="pn">0</span><span class="pct-s">%</span></div>
        <div class="gauge-lbl">مصرف حجم</div>
      </div>
    </div>
    <div class="gauge-stats">
      <div class="gs"><div class="gv">__USED__</div><div class="gl">مصرف‌شده</div></div>
      <div class="gs"><div class="gv">__REMAIN__</div><div class="gl">باقی‌مانده</div></div>
      <div class="gs"><div class="gv">__LIMIT__</div><div class="gl">کل سهمیه</div></div>
    </div>
  </div>
  <div class="info-grid">
    <div class="info-card"><div class="info-lbl">اتصال همزمان</div><div class="info-val">__MAXCONN__</div></div>
    <div class="info-card"><div class="info-lbl">تاریخ انقضا</div><div class="info-val sm">__EXPIRY__</div></div>
    <div class="info-card" style="grid-column:1/-1"><div class="info-lbl">زمان باقی‌مانده</div><div class="info-val countdown" id="cd" data-exp="__EXP_EPOCH__">__REMAIN_TIME__</div></div>
  </div>
  <div class="config-sec">
    <div class="sec-label" style="margin-bottom:6px">کانفیگ VLESS</div>
    <div class="config-box" id="cfg">__VLESS__</div>
    <div class="btn-row">
      <button class="btn btn-primary" onclick="copyCfg()">کپی کانفیگ</button>
      <button class="btn btn-ghost" onclick="dlCfg()">دانلود</button>
    </div>
  </div>
  <div class="footer">
    <span class="badge">Usf __VERSION__</span>
    <span style="color:__STATUS_COLOR__;font-weight:600">__STATUS_TEXT__</span>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
var SU="__SUB_URL_JSON__",VL="__VLESS_JSON__",PC=__PCT_NUM__;
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);try{localStorage.setItem('usf-t',t)}catch(e){}}
function toggleTheme(){var c=document.documentElement.getAttribute('data-theme')||'dark';applyTheme(c==='dark'?'light':'dark')}
(function(){var s;try{s=localStorage.getItem('usf-t')}catch(e){}if(!s){s=window.matchMedia&&window.matchMedia('(prefers-color-scheme:light)').matches?'light':'dark'}applyTheme(s)})();
(function(){var f=document.getElementById('gf'),p=document.getElementById('pn'),C=2*Math.PI*60,t=Math.max(0,Math.min(100,PC)),st=null;
function step(ts){if(!st)st=ts;var pr=Math.min(1,(ts-st)/1200),e=1-Math.pow(1-pr,3);f.style.strokeDashoffset=(C*(1-t*e/100)).toFixed(2);p.textContent=Math.round(t*e);if(pr<1)requestAnimationFrame(step)}requestAnimationFrame(step)})();
(function(){var el=document.getElementById('cd');if(!el)return;var exp=parseInt(el.dataset.exp,10);if(!exp)return;
function tick(){var d=exp-Math.floor(Date.now()/1000);if(d<=0){el.textContent='منقضی شده';el.style.color='var(--red)';return}
var dd=Math.floor(d/86400),h=Math.floor((d%86400)/3600),m=Math.floor((d%3600)/60),s=d%60,txt='';if(dd>0)txt+=dd+' روز و ';
txt+=(h<10?'0':'')+h+':';txt+=(m<10?'0':'')+m+':';txt+=(s<10?'0':'')+s;el.textContent=txt}tick();setInterval(tick,1000)})();
function copySub(){navigator.clipboard.writeText(SU).then(function(){showToast('لینک اشتراک کپی شد')}).catch(function(){showToast('کپی ناموفق',true)})}
function copyCfg(){navigator.clipboard.writeText(VL).then(function(){showToast('کانفیگ کپی شد')}).catch(function(){showToast('کپی ناموفق',true)})}
function dlCfg(){try{var b=new Blob([VL],{type:'text/plain;charset=utf-8'}),u=URL.createObjectURL(b),a=document.createElement('a');a.href=u;a.download='__LABEL_SAFE__.txt';document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(u);showToast('دانلود شد')}catch(e){showToast('خطا',true)}}
var _tt;function showToast(m,e){var t=document.getElementById('toast');t.textContent=m;t.style.borderColor=e?'rgba(239,68,68,0.4)':'var(--border)';t.classList.add('show');clearTimeout(_tt);_tt=setTimeout(function(){t.classList.remove('show')},2500)}
</script>
</body></html>'''


@app.get("/status/{uuid}", response_class=HTMLResponse)
async def subscription_status(uuid: str):
    async with LINKS_LOCK:
        link_data = LINKS.get(uuid)
        if link_data is None:
            return HTMLResponse(content=STATUS_404_HTML, status_code=404)

    used_bytes = int(link_data.get("used_bytes", 0))
    limit_bytes = int(link_data.get("limit_bytes", 0))
    remaining_bytes = max(0, limit_bytes - used_bytes) if limit_bytes > 0 else 0
    _domain = get_domain()
    sub_url = f"https://{_domain}/sub/{uuid}" if _domain and _domain != "localhost" else f"/sub/{uuid}"
    percent = min(100, (used_bytes / limit_bytes) * 100) if limit_bytes > 0 else 0

    used_str = fmt_bytes(used_bytes)
    limit_str = fmt_bytes(limit_bytes) if limit_bytes > 0 else "نامحدود"
    remaining_str = fmt_bytes(remaining_bytes) if limit_bytes > 0 else "نامحدود"

    expiry_raw = link_data.get('expiry', '')
    expiry_display = "نامحدود"
    expiry_epoch_val = 0
    if expiry_raw:
        try:
            exp_dt = datetime.fromisoformat(expiry_raw)
            expiry_epoch_val = int(exp_dt.timestamp())
            expiry_display = exp_dt.strftime('%Y-%m-%d')
        except (TypeError, ValueError):
            expiry_raw = ''

    label = link_data.get('label', 'بدون نام')
    max_conn = link_data.get('max_connections', 0)
    is_active = bool(link_data.get('active', False))
    is_exp = is_expired(link_data)
    status_text = 'فعال' if (is_active and not is_exp) else ('منقضی' if is_exp else 'غیرفعال')
    status_color = '#22c55e' if (is_active and not is_exp) else ('#ef4444' if is_exp else '#f59e0b')

    if not expiry_raw:
        remain_time_display = "نامحدود"
    elif expiry_epoch_val and expiry_epoch_val > time.time():
        diff = expiry_epoch_val - int(time.time())
        d = diff // 86400; h = (diff % 86400) // 3600; m = (diff % 3600) // 60
        if d > 0: remain_time_display = f"{d} روز و {h:02d}:{m:02d}"
        elif h > 0: remain_time_display = f"{h:02d}:{m:02d}:{diff % 60:02d}"
        else: remain_time_display = f"{m:02d}:{diff % 60:02d}"
    else:
        remain_time_display = "منقضی شده"

    max_conn_disp = str(max_conn) if max_conn and max_conn > 0 else 'نامحدود'
    vless_link = generate_vless_link(uuid, remark=f"{label}")

    label_h = _hesc(str(label))
    sub_url_h = _hesc(sub_url, quote=True)
    sub_url_j = json.dumps(sub_url)
    sub_url_enc = quote(sub_url, safe='')
    sub_url_b64 = base64.b64encode(sub_url.encode()).decode().rstrip('=')
    vless_h = _hesc(vless_link)
    vless_j = json.dumps(vless_link)
    label_safe = re.sub(r'[^a-zA-Z0-9\-_.]', '_', str(label))

    # Status banner styles
    if is_active and not is_exp:
        status_style = 'background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);color:#22c55e'
        dot_style = f'background:{status_color};box-shadow:0 0 10px {status_color}'
    elif is_exp:
        status_style = 'background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);color:#ef4444'
        dot_style = f'background:{status_color};box-shadow:0 0 10px {status_color}'
    else:
        status_style = 'background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);color:#f59e0b'
        dot_style = f'background:{status_color};box-shadow:0 0 10px {status_color}'

    html_content = (STATUS_HTML_TEMPLATE
        .replace('__TITLE__', _hesc(f'اشتراک {label}'))
        .replace('__LABEL__', label_h)
        .replace('__STATUS_TEXT__', _hesc(status_text))
        .replace('__STATUS_COLOR__', status_color)
        .replace('__STATUS_STYLE__', status_style)
        .replace('__DOT_STYLE__', dot_style)
        .replace('__SUB_URL__', sub_url_h)
        .replace('__SUB_URL_ENC__', sub_url_enc)
        .replace('__SUB_URL_B64__', sub_url_b64)
        .replace('__SUB_URL_JSON__', sub_url_j)
        .replace('__USED__', _hesc(used_str))
        .replace('__LIMIT__', _hesc(limit_str))
        .replace('__REMAIN__', _hesc(remaining_str))
        .replace('__PCT_NUM__', f"{percent:.1f}")
        .replace('__MAXCONN__', _hesc(max_conn_disp))
        .replace('__EXPIRY__', _hesc(expiry_display))
        .replace('__EXP_EPOCH__', str(expiry_epoch_val))
        .replace('__REMAIN_TIME__', _hesc(remain_time_display))
        .replace('__VLESS__', vless_h)
        .replace('__VLESS_JSON__', vless_j)
        .replace('__VERSION__', _hesc(str(PANEL_VERSION)))
        .replace('__LABEL_SAFE__', _hesc(label_safe))
    )
    return HTMLResponse(content=html_content)

#  USF Panel v2.0.0 — Login Page
# ============================================================

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Usf - Login</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:#0b0f1a;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem;
background-image:radial-gradient(ellipse 80% 50% at 50% -20%,rgba(99,102,241,0.1),transparent 60%),radial-gradient(ellipse 60% 40% at 80% 100%,rgba(139,92,246,0.06),transparent 50%)}
#login{background:rgba(15,23,42,0.6);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border:1px solid rgba(99,102,241,0.15);border-radius:20px;padding:2.5rem 2rem 2rem;width:100%;max-width:380px;position:relative;animation:charge .5s ease both}
@keyframes charge{0%{transform:translateY(1.5rem);opacity:0}100%{transform:translateY(0);opacity:1}}
#login::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#6366f1 30%,#a78bfa 50%,#6366f1 70%,transparent);opacity:.5;border-radius:20px 20px 0 0}
.theme-btn{position:absolute;top:14px;right:14px;width:34px;height:34px;border-radius:50%;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.06);color:#94a3b8;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .25s}
.theme-btn:hover{background:rgba(99,102,241,0.12);color:#a78bfa}
.theme-btn svg{width:16px;height:16px}
.logo{font-size:2rem;font-weight:800;text-align:center;margin-bottom:.5rem;letter-spacing:-.03em;background:linear-gradient(135deg,#f1f5f9,#818cf8);-webkit-background-clip:text;background-clip:text;color:transparent}
.subtitle{text-align:center;color:#64748b;font-size:13px;margin-bottom:2rem}
.fields{display:flex;flex-direction:column;gap:12px;margin-bottom:1.5rem}
.field{display:flex;align-items:center;background:rgba(255,255,255,0.03);border:1.5px solid rgba(255,255,255,0.06);border-radius:12px;padding:0 14px;height:48px;transition:border-color .3s}
.field:focus-within{border-color:rgba(99,102,241,0.5);box-shadow:0 0 0 3px rgba(99,102,241,0.1)}
.field svg{flex-shrink:0;color:#475569}
.field input{flex:1;background:transparent;border:none;outline:none;color:#f1f5f9;font-size:13px;height:100%;padding:0 10px;font-family:inherit}
.field input::placeholder{color:#475569}
.field .eye{cursor:pointer;color:#475569;padding:0 2px;transition:color .2s}
.field .eye:hover{color:#818cf8}
.login-btn{width:100%;height:46px;border:none;border-radius:12px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;font-size:14px;font-weight:600;cursor:pointer;transition:all .3s;letter-spacing:.3px;font-family:inherit}
.login-btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(99,102,241,0.3)}
.login-btn:active{transform:translateY(0)}
.err{color:#ef4444;text-align:center;font-size:12px;padding:8px;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.15);border-radius:8px;display:none;margin-top:8px}
.err.show{display:block}
html[data-theme="light"] body{background:#f1f5f9}
html[data-theme="light"] #login{background:rgba(255,255,255,0.8);border-color:rgba(99,102,241,0.15)}
html[data-theme="light"] .field{background:rgba(0,0,0,0.03);border-color:rgba(0,0,0,0.08)}
html[data-theme="light"] .field input{color:#0f172a}
html[data-theme="light"] .field svg,.html[data-theme="light"] .field .eye{color:#94a3b8}
html[data-theme="light"] .err{background:rgba(239,68,68,0.06)}
</style>
</head>
<body>
<div id="login">
  <button class="theme-btn" onclick="toggleTheme()">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
  </button>
  <div class="logo">Usf</div>
  <div class="subtitle">Panel Management</div>
  <form id="login-form">
    <div class="fields">
      <div class="field">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        <input placeholder="Username" type="text" name="username" autocomplete="username" id="username" value="admin">
      </div>
      <div class="field">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        <input placeholder="Password" type="password" name="password" autocomplete="current-password" id="password">
        <span class="eye" onclick="togglePw()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </span>
      </div>
    </div>
    <div class="err" id="err-msg"></div>
    <button type="submit" class="login-btn">Sign In</button>
  </form>
</div>
<script>
let dark=true;
function toggleTheme(){dark=!dark;document.documentElement.setAttribute('data-theme',dark?'dark':'light')}
function togglePw(){var i=document.getElementById('password');i.type=i.type==='password'?'text':'password'}
document.getElementById('login-form').addEventListener('submit',async(e)=>{
  e.preventDefault();var err=document.getElementById('err-msg');err.classList.remove('show');
  var u=document.getElementById('username').value,p=document.getElementById('password').value;
  try{var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({username:u,password:p})});
  if(!r.ok){var d=await r.json().catch(()=>({}));err.textContent=d.detail||'Invalid credentials';err.classList.add('show');return}
  window.location.href='/dashboard'}catch(e){err.textContent='Connection error';err.classList.add('show')}
});
</script>
</body>
</html>"""

#  USF Panel v2.0.0 — Dashboard HTML
# ============================================================

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Usf - Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0b0f1a;--surface:#111827;--surface2:#1e293b;--border:rgba(99,102,241,0.12);
  --border2:rgba(255,255,255,0.06);--text:#f1f5f9;--text2:#cbd5e1;--text3:#94a3b8;
  --text4:#64748b;--accent:#6366f1;--accent2:#818cf8;--accent-soft:rgba(99,102,241,0.1);
  --green:#22c55e;--red:#ef4444;--amber:#f59e0b;--purple:#a78bfa;
  --radius:12px;--sidebar-w:220px;
}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text2);min-height:100vh;display:flex}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--surface2);border-radius:3px}

/* Sidebar */
.sidebar{width:var(--sidebar-w);height:100vh;background:var(--surface);border-right:1px solid var(--border2);
  position:fixed;left:0;top:0;bottom:0;z-index:100;display:flex;flex-direction:column;transition:transform .3s ease}
.sidebar-header{padding:16px;border-bottom:1px solid var(--border2)}
.brand{display:flex;align-items:center;gap:10px}
.brand-logo{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--purple));display:flex;align-items:center;justify-content:center;font-weight:800;font-size:14px;color:#fff}
.brand-name{font-size:15px;font-weight:700;color:var(--text)}
.brand-ver{font-size:9px;color:var(--text4);background:var(--accent-soft);padding:2px 7px;border-radius:4px;margin-left:auto;font-weight:600}
.sidebar-nav{flex:1;padding:8px;overflow-y:auto}
.nav-section{font-size:9px;font-weight:700;color:var(--text4);text-transform:uppercase;letter-spacing:.1em;padding:12px 12px 4px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;color:var(--text3);font-size:13px;cursor:pointer;transition:all .15s;border:none;background:none;width:100%;text-align:left;margin:1px 0;font-family:inherit}
.nav-item:hover{background:var(--accent-soft);color:var(--text)}
.nav-item.active{background:var(--accent-soft);color:var(--accent2);font-weight:600}
.nav-item svg{width:16px;height:16px;flex-shrink:0}
.nav-badge{margin-left:auto;background:var(--surface2);color:var(--text4);font-size:10px;padding:1px 7px;border-radius:6px;font-weight:600}
.sidebar-footer{padding:10px;border-top:1px solid var(--border2)}
.logout-btn{width:100%;padding:8px;border:1px solid var(--border2);border-radius:8px;background:none;color:var(--text4);font-family:inherit;font-size:11px;font-weight:600;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:6px}
.logout-btn:hover{background:rgba(239,68,68,0.08);border-color:rgba(239,68,68,0.2);color:var(--red)}
.hamburger{display:none;position:fixed;top:12px;left:12px;z-index:200;width:36px;height:36px;border-radius:8px;background:var(--surface);border:1px solid var(--border2);color:var(--text2);cursor:pointer;align-items:center;justify-content:center}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:99}
.overlay.show{display:block}

/* Main content */
.main{flex:1;margin-left:var(--sidebar-w);padding:20px 24px 48px;min-height:100vh}
.page{display:none;animation:pageIn .3s ease}.page.active{display:block}
@keyframes pageIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}

/* Cards */
.card{background:var(--surface);border:1px solid var(--border2);border-radius:var(--radius);padding:16px;margin-bottom:12px;transition:box-shadow .2s}
.card:hover{box-shadow:0 2px 12px rgba(0,0,0,.2)}
.card-head{display:flex;align-items:center;justify-content:space-between;padding-bottom:12px;border-bottom:1px solid var(--border2);margin-bottom:12px}
.card-title{font-size:14px;font-weight:600;color:var(--text)}
.card-extra{color:var(--text4);font-size:12px}

/* Stat grid */
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:12px}
.stat-card{background:var(--surface);border:1px solid var(--border2);border-radius:var(--radius);padding:14px;position:relative;overflow:hidden}
.stat-card::after{content:'';position:absolute;top:0;right:0;width:40px;height:40px;border-radius:0 0 0 40px;opacity:.06}
.stat-card:nth-child(1)::after{background:var(--accent)}.stat-card:nth-child(2)::after{background:var(--green)}
.stat-card:nth-child(3)::after{background:var(--amber)}.stat-card:nth-child(4)::after{background:var(--purple)}
.stat-label{font-size:10px;color:var(--text4);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;font-weight:600}
.stat-value{font-size:18px;font-weight:700;color:var(--text);font-family:'JetBrains Mono',monospace}
.stat-sub{font-size:10px;color:var(--text4);margin-top:4px}

/* Gauge row */
.gauge-row{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:12px}
.gauge-card{background:var(--surface);border:1px solid var(--border2);border-radius:var(--radius);padding:14px;text-align:center}
.gauge-card svg{width:80px;height:80px;margin:0 auto 6px;display:block}
.gauge-card .g-label{font-size:10px;color:var(--text4);text-transform:uppercase;letter-spacing:.05em;font-weight:600}
.gauge-card .g-value{font-size:11px;color:var(--text3);margin-top:2px;font-family:'JetBrains Mono',monospace}

/* Tags & Badges */
.tag{display:inline-flex;align-items:center;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600}
.tag-green{background:rgba(34,197,94,0.12);color:#22c55e;border:1px solid rgba(34,197,94,0.15)}
.tag-red{background:rgba(239,68,68,0.08);color:#ef4444;border:1px solid rgba(239,68,68,0.12)}
.tag-purple{background:rgba(167,139,250,0.12);color:#a78bfa;border:1px solid rgba(167,139,250,0.15)}
.tag-amber{background:rgba(245,158,11,0.12);color:#f59e0b;border:1px solid rgba(245,158,11,0.15)}
.badge-dot{width:7px;height:7px;border-radius:50%;display:inline-block}
.badge-dot.green{background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse 1.2s ease-in-out infinite}
.badge-dot.red{background:var(--red)}
@keyframes pulse{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.4);opacity:.4}}

/* Buttons */
.btn{font-family:inherit;font-size:12px;font-weight:600;border-radius:8px;padding:7px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:5px;border:none;transition:all .15s}
.btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:var(--accent2)}
.btn-secondary{background:var(--surface2);color:var(--text3);border:1px solid var(--border2)}.btn-secondary:hover{border-color:var(--accent);color:var(--accent)}
.btn-danger{background:rgba(239,68,68,0.08);color:var(--red);border:1px solid rgba(239,68,68,0.1)}.btn-danger:hover{background:rgba(239,68,68,0.15)}
.btn-sm{padding:4px 9px;font-size:11px}
.btn-icon{width:28px;height:28px;padding:0;justify-content:center;border-radius:6px;font-size:12px;font-weight:700}

/* Table */
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;color:var(--text4);font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.05em;padding:10px 12px;border-bottom:1px solid var(--border2)}
td{padding:10px 12px;border-bottom:1px solid var(--border2);color:var(--text2);vertical-align:middle}
tr:hover td{background:rgba(99,102,241,0.03)}

/* Usage bar */
.usage-pill{display:flex;align-items:center;gap:8px;min-width:140px}
.usage-pill .used{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text);white-space:nowrap;min-width:55px}
.usage-pill .bar{flex:1;height:4px;background:var(--surface2);border-radius:2px;overflow:hidden;min-width:40px}
.usage-pill .bar .fill{height:100%;border-radius:2px;transition:width .5s}
.usage-pill .limit{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text4);white-space:nowrap}

/* Filter chips */
.chips{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.chip{padding:5px 12px;border-radius:8px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid var(--border2);background:transparent;color:var(--text4);transition:all .15s;font-family:inherit}
.chip:hover{border-color:var(--accent);color:var(--text2)}
.chip.active{background:var(--accent-soft);border-color:var(--accent);color:var(--accent2)}
.search-box{display:flex;align-items:center;background:var(--surface2);border:1px solid var(--border2);border-radius:8px;padding:0 12px;height:34px;margin-bottom:12px;transition:border-color .2s}
.search-box:focus-within{border-color:var(--accent)}
.search-box svg{width:14px;height:14px;color:var(--text4);flex-shrink:0}
.search-box input{flex:1;background:transparent;border:none;outline:none;color:var(--text);font-size:12px;padding:0 8px;font-family:inherit}
.search-box input::placeholder{color:var(--text4)}

/* Modal */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);z-index:300;align-items:center;justify-content:center;padding:20px}
.modal-overlay.show{display:flex}
.modal{background:var(--surface);border:1px solid var(--border2);border-radius:16px;padding:24px;width:100%;max-width:440px;max-height:90vh;overflow-y:auto;animation:modalIn .25s ease}
@keyframes modalIn{from{opacity:0;transform:scale(.96)}to{opacity:1;transform:none}}
.modal-close{position:absolute;top:12px;right:12px;width:28px;height:28px;border-radius:6px;background:var(--surface2);border:none;color:var(--text4);cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center;transition:all .15s}
.modal-close:hover{background:rgba(239,68,68,0.1);color:var(--red)}
.modal-title{font-size:16px;font-weight:700;color:var(--text);margin-bottom:16px;position:relative}
.form-group{margin-bottom:12px}
.form-label{display:block;font-size:11px;font-weight:600;color:var(--text3);margin-bottom:5px;text-transform:uppercase;letter-spacing:.04em}
.form-input{width:100%;height:40px;background:var(--surface2);border:1px solid var(--border2);border-radius:8px;padding:0 12px;color:var(--text);font-size:13px;font-family:inherit;outline:none;transition:border-color .2s}
.form-input:focus{border-color:var(--accent)}
.form-select{width:100%;height:40px;background:var(--surface2);border:1px solid var(--border2);border-radius:8px;padding:0 12px;color:var(--text);font-size:13px;font-family:inherit;outline:none;appearance:none;cursor:pointer}
.form-row{display:flex;gap:8px}
.form-row .form-group{flex:1}

/* Info rows */
.info-row{display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border2)}
.info-row:last-child{border-bottom:none}
.info-label{font-size:12px;color:var(--text3)}
.info-value{font-size:13px;color:var(--text);font-weight:600;font-family:'JetBrains Mono',monospace}

/* Toast */
.toast{position:fixed;bottom:20px;right:20px;padding:10px 18px;border-radius:10px;font-size:12px;font-weight:500;z-index:1000;transform:translateY(80px);opacity:0;transition:all .3s ease;pointer-events:none}
.toast.show{transform:translateY(0);opacity:1}
.toast.success{background:rgba(34,197,94,0.15);color:var(--green);border:1px solid rgba(34,197,94,0.2)}
.toast.error{background:rgba(239,68,68,0.15);color:var(--red);border:1px solid rgba(239,68,68,0.2)}

/* Chart container */
.chart-container{position:relative;height:200px;margin-top:8px}

/* Address item */
.addr-item{display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:var(--surface2);border:1px solid var(--border2);border-radius:8px;margin-bottom:6px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text2)}

/* IP blur */
.ip-val{filter:blur(4px);cursor:pointer;transition:filter .2s}.ip-val.visible{filter:none}

/* Panel builder */
.builder-card{background:linear-gradient(135deg,var(--surface),rgba(99,102,241,0.05));border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:12px}
.builder-title{font-size:16px;font-weight:700;color:var(--text);margin-bottom:4px}
.builder-desc{font-size:12px;color:var(--text3);margin-bottom:16px;line-height:1.6}
.builder-steps{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.builder-step{flex:1;min-width:120px;padding:12px;background:var(--surface2);border:1px solid var(--border2);border-radius:10px;text-align:center}
.builder-step .step-num{width:24px;height:24px;border-radius:50%;background:var(--accent);color:#fff;font-size:11px;font-weight:700;display:inline-flex;align-items:center;justify-content:center;margin-bottom:6px}
.builder-step .step-text{font-size:11px;color:var(--text3)}

/* Responsive */
@media(max-width:1024px){.stat-grid{grid-template-columns:repeat(2,1fr)}.gauge-row{grid-template-columns:repeat(2,1fr)}}
@media(max-width:768px){
  .sidebar{transform:translateX(-100%)}.sidebar.open{transform:translateX(0)}
  .hamburger{display:flex}.main{margin-left:0;padding:16px}
  .stat-grid{grid-template-columns:1fr 1fr}.gauge-row{grid-template-columns:1fr 1fr}
}
@media(max-width:480px){.stat-grid,.gauge-row{grid-template-columns:1fr}}
</style>
</head>
<body>

<button class="hamburger" onclick="toggleSidebar()">
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
</button>
<div class="overlay" id="overlay" onclick="closeSidebar()"></div>

<!-- Sidebar -->
<aside class="sidebar" id="sidebar">
  <div class="sidebar-header">
    <div class="brand">
      <div class="brand-logo">U</div>
      <span class="brand-name">Usf</span>
      <span class="brand-ver" id="ver-badge">v2.0.0</span>
    </div>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-section">Main</div>
    <button class="nav-item active" onclick="go('overview',this)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
      Overview
    </button>
    <button class="nav-item" onclick="go('inbounds',this)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1"/></svg>
      Inbounds
      <span class="nav-badge" id="links-badge">0</span>
    </button>
    <div class="nav-section">Network</div>
    <button class="nav-item" onclick="go('cleanip',this)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
      Clean IP
    </button>
    <button class="nav-item" onclick="go('domain',this)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
      Domain
    </button>
    <div class="nav-section">Tools</div>
    <button class="nav-item" onclick="go('builder',this)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
      Panel Builder
    </button>
    <button class="nav-item" onclick="go('settings',this)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
      Settings
    </button>
  </nav>
  <div class="sidebar-footer">
    <button class="logout-btn" onclick="doLogout()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      Sign Out
    </button>
  </div>
</aside>

<!-- Main -->
<div class="main">

<!-- Overview Page -->
<section class="page active" id="page-overview">
  <div class="stat-grid">
    <div class="stat-card">
      <div class="stat-label">Active Connections</div>
      <div class="stat-value" id="s-conn">0</div>
      <div class="stat-sub" id="s-tcp-udp">TCP: 0 | UDP: 0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Upload / Download</div>
      <div class="stat-value" style="font-size:14px"><span id="s-up">--</span> / <span id="s-down">--</span></div>
      <div class="stat-sub">per second</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Total Traffic</div>
      <div class="stat-value" id="s-traffic">0 MB</div>
      <div class="stat-sub">Sent: <span id="s-sent">--</span> | Recv: <span id="s-recv">--</span></div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Service Status</div>
      <div style="display:flex;align-items:center;gap:8px;margin-top:4px">
        <span class="badge-dot green" id="xray-dot"></span>
        <span style="font-weight:600;color:var(--text)" id="xray-status-text">Running</span>
      </div>
      <div class="stat-sub">Uptime: <span id="s-uptime">--</span></div>
    </div>
  </div>

  <div class="gauge-row">
    <div class="gauge-card">
      <svg viewBox="0 0 80 80"><circle cx="40" cy="40" r="32" fill="none" stroke="var(--surface2)" stroke-width="5"/><circle id="g-cpu" cx="40" cy="40" r="32" fill="none" stroke="var(--accent)" stroke-width="5" stroke-linecap="round" stroke-dasharray="201" stroke-dashoffset="201" transform="rotate(-90 40 40)" style="transition:stroke-dashoffset .5s"/></svg>
      <div class="g-label">CPU</div>
      <div class="g-value" id="g-cpu-t">0%</div>
    </div>
    <div class="gauge-card">
      <svg viewBox="0 0 80 80"><circle cx="40" cy="40" r="32" fill="none" stroke="var(--surface2)" stroke-width="5"/><circle id="g-ram" cx="40" cy="40" r="32" fill="none" stroke="var(--green)" stroke-width="5" stroke-linecap="round" stroke-dasharray="201" stroke-dashoffset="201" transform="rotate(-90 40 40)" style="transition:stroke-dashoffset .5s"/></svg>
      <div class="g-label">RAM</div>
      <div class="g-value" id="g-ram-t">0%</div>
    </div>
    <div class="gauge-card">
      <svg viewBox="0 0 80 80"><circle cx="40" cy="40" r="32" fill="none" stroke="var(--surface2)" stroke-width="5"/><circle id="g-swap" cx="40" cy="40" r="32" fill="none" stroke="var(--amber)" stroke-width="5" stroke-linecap="round" stroke-dasharray="201" stroke-dashoffset="201" transform="rotate(-90 40 40)" style="transition:stroke-dashoffset .5s"/></svg>
      <div class="g-label">Swap</div>
      <div class="g-value" id="g-swap-t">0%</div>
    </div>
    <div class="gauge-card">
      <svg viewBox="0 0 80 80"><circle cx="40" cy="40" r="32" fill="none" stroke="var(--surface2)" stroke-width="5"/><circle id="g-disk" cx="40" cy="40" r="32" fill="none" stroke="var(--purple)" stroke-width="5" stroke-linecap="round" stroke-dasharray="201" stroke-dashoffset="201" transform="rotate(-90 40 40)" style="transition:stroke-dashoffset .5s"/></svg>
      <div class="g-label">Disk</div>
      <div class="g-value" id="g-disk-t">0%</div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="card-title">Traffic (24h)</div>
      <div style="display:flex;gap:6px">
        <button class="btn btn-sm btn-secondary" onclick="openLogs()">Logs</button>
        <button class="btn btn-sm btn-secondary" onclick="openConfig()">Config</button>
        <button class="btn btn-sm btn-primary" onclick="downloadBackup()">Backup</button>
      </div>
    </div>
    <div class="chart-container"><canvas id="trafficChart"></canvas></div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="card-title">System Info</div>
      <div class="card-extra"><span class="tag tag-purple">Panel <span id="pv-tag">v2.0.0</span></span> <span class="tag tag-green" id="tg-tag"></span></div>
    </div>
    <div class="info-row"><span class="info-label">Domain</span><span class="info-value" id="s-domain">--</span></div>
    <div class="info-row"><span class="info-label">IPv4</span><span class="info-value ip-val" id="s-ipv4" onclick="toggleIps()">N/A</span></div>
    <div class="info-row"><span class="info-label">IPv6</span><span class="info-value ip-val" id="s-ipv6" onclick="toggleIps()">N/A</span></div>
    <div class="info-row"><span class="info-label">System Load</span><span class="info-value" id="s-load">--</span></div>
    <div class="info-row"><span class="info-label">App RAM / Threads</span><span class="info-value" id="s-ram-th">--</span></div>
    <div class="info-row"><span class="info-label">OS Uptime</span><span class="info-value" id="s-os-up">--</span></div>
  </div>
</section>

<!-- Inbounds Page -->
<section class="page" id="page-inbounds">
  <div class="card" style="margin-bottom:12px">
    <div class="card-head">
      <div class="card-title">Inbounds</div>
      <button class="btn btn-primary btn-sm" onclick="showModal('add-modal')">+ New Inbound</button>
    </div>
    <div class="stat-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:12px">
      <div style="text-align:center"><div style="font-size:18px;font-weight:700;color:var(--text)" id="ib-total">0</div><div style="font-size:10px;color:var(--text4)">Total</div></div>
      <div style="text-align:center"><div style="font-size:18px;font-weight:700;color:var(--green)" id="ib-active">0</div><div style="font-size:10px;color:var(--text4)">Active</div></div>
      <div style="text-align:center"><div style="font-size:18px;font-weight:700;color:var(--text)" id="ib-traffic">0 MB</div><div style="font-size:10px;color:var(--text4)">Proxy Traffic</div></div>
      <div style="text-align:center"><div style="font-size:18px;font-weight:700;color:var(--text)" id="ib-requests">0</div><div style="font-size:10px;color:var(--text4)">Requests</div></div>
    </div>
    <div class="chips">
      <button class="chip active" onclick="setFilter('all',this)">All</button>
      <button class="chip" onclick="setFilter('active',this)">Active</button>
      <button class="chip" onclick="setFilter('disabled',this)">Disabled</button>
      <button class="chip" onclick="setFilter('expired',this)">Expired</button>
    </div>
    <div class="search-box">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <input placeholder="Search by name or UUID..." id="inbound-search" oninput="filterInbounds()">
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>#</th><th>Name</th><th>Type</th><th>Traffic</th><th>Connections</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody id="inbounds-tbody"></tbody>
      </table>
    </div>
  </div>
</section>

<!-- Clean IP Page -->
<section class="page" id="page-cleanip">
  <div class="card">
    <div class="card-head">
      <div class="card-title">Clean IP / Domain Addresses</div>
      <button class="btn btn-primary btn-sm" onclick="showModal('addr-modal')">+ Add</button>
    </div>
    <p style="font-size:12px;color:var(--text3);margin-bottom:12px">These addresses are used as the connection address in VLESS links. The actual SNI/host remains your domain.</p>
    <div id="address-list"></div>
  </div>
</section>

<!-- Domain Page -->
<section class="page" id="page-domain">
  <div class="card">
    <div class="card-head"><div class="card-title">Custom Domain</div></div>
    <p style="font-size:12px;color:var(--text3);margin-bottom:12px">Set a custom domain for generating VLESS links. Leave empty to use the default HF domain.</p>
    <div class="info-row"><span class="info-label">Render Domain</span><span class="info-value" id="rd-domain">--</span></div>
    <div class="info-row"><span class="info-label">Custom Domain</span><span class="info-value" id="dv-domain" style="cursor:pointer">--</span></div>
    <div style="margin-top:12px">
      <div class="form-row">
        <div class="form-group" style="flex:3"><input class="form-input" id="domain-input" placeholder="e.g. mypanel.com"></div>
        <button class="btn btn-primary" style="height:40px" onclick="saveDomain()">Save</button>
      </div>
      <button class="btn btn-danger btn-sm" id="domain-clear-btn" style="display:none;margin-top:6px" onclick="clearDomain()">Clear Custom Domain</button>
    </div>
  </div>
</section>

<!-- Panel Builder Page -->
<section class="page" id="page-builder">
  <div class="builder-card">
    <div class="builder-title">Panel Builder</div>
    <div class="builder-desc">Create a new Usf panel on your HuggingFace account with just a few clicks. Your HF token must have write access to Spaces.</div>
    <div class="builder-steps">
      <div class="builder-step"><div class="step-num">1</div><div class="step-text">Enter HF Token</div></div>
      <div class="builder-step"><div class="step-num">2</div><div class="step-text">Choose Space Name</div></div>
      <div class="builder-step"><div class="step-num">3</div><div class="step-text">Set Credentials</div></div>
      <div class="builder-step"><div class="step-num">4</div><div class="step-text">Deploy</div></div>
    </div>
    <div class="form-group"><label class="form-label">HuggingFace Token</label><input class="form-input" id="pb-token" type="password" placeholder="hf_xxxxxxxxxxxxxxxxxx"></div>
    <div class="form-group"><label class="form-label">Space Name (lowercase)</label><input class="form-input" id="pb-space" placeholder="my-usf-panel"></div>
    <div class="form-row">
      <div class="form-group"><label class="form-label">Admin Username</label><input class="form-input" id="pb-user" value="admin"></div>
      <div class="form-group"><label class="form-label">Admin Password</label><input class="form-input" id="pb-pass" type="password" value="admin" placeholder="min 4 chars"></div>
    </div>
    <button class="btn btn-primary" style="width:100%;justify-content:center;height:44px;font-size:14px;margin-top:4px" onclick="deployPanel()">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>
      Deploy Panel
    </button>
    <div id="pb-result" style="margin-top:12px;display:none"></div>
  </div>
</section>

<!-- Settings Page -->
<section class="page" id="page-settings">
  <div class="card">
    <div class="card-head"><div class="card-title">Change Password</div></div>
    <div class="form-group"><label class="form-label">Current Password</label><input class="form-input" id="cur-pw" type="password"></div>
    <div class="form-group"><label class="form-label">New Password</label><input class="form-input" id="new-pw" type="password"></div>
    <div class="form-group"><label class="form-label">Confirm New Password</label><input class="form-input" id="cfm-pw" type="password"></div>
    <button class="btn btn-primary" style="width:100%;justify-content:center;margin-top:4px" onclick="changePassword()">Update Password</button>
  </div>
</section>

</div>

<!-- Modals -->
<div class="modal-overlay" id="add-modal" onclick="if(event.target===this)closeModal('add-modal')">
  <div class="modal" style="position:relative">
    <button class="modal-close" onclick="closeModal('add-modal')">&times;</button>
    <div class="modal-title">New Inbound</div>
    <div class="form-group"><label class="form-label">Name</label><input class="form-input" id="n-label" placeholder="e.g. User1"></div>
    <div class="form-row">
      <div class="form-group"><label class="form-label">Traffic Limit</label><input class="form-input" id="n-limit" type="number" min="0" step="0.1" placeholder="0 = Unlimited"></div>
      <div class="form-group" style="max-width:90px"><label class="form-label">Unit</label><select class="form-select" id="n-unit"><option value="GB">GB</option><option value="MB">MB</option></select></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label class="form-label">Max Connections (0 = Unlimited)</label><input class="form-input" id="n-maxconn" type="number" min="0" placeholder="0"></div>
      <div class="form-group"><label class="form-label">Expiry Days (0 = Never)</label><input class="form-input" id="n-expiry" type="number" min="0" placeholder="0"></div>
    </div>
    <div class="form-group"><label class="form-label">Tag (optional)</label><input class="form-input" id="n-tag" placeholder="e.g. VIP, Trial"></div>
    <button class="btn btn-primary" style="width:100%;justify-content:center;margin-top:4px" onclick="createInbound()">Create Inbound</button>
  </div>
</div>

<div class="modal-overlay" id="edit-modal" onclick="if(event.target===this)closeModal('edit-modal')">
  <div class="modal" style="position:relative">
    <button class="modal-close" onclick="closeModal('edit-modal')">&times;</button>
    <div class="modal-title" id="edit-title">Edit Inbound</div>
    <input type="hidden" id="edit-uid">
    <div class="form-group"><label class="form-label">Name (read-only)</label><input class="form-input" id="e-name" readonly style="opacity:.5;cursor:not-allowed"></div>
    <div class="form-row">
      <div class="form-group"><label class="form-label">Traffic Limit</label><input class="form-input" id="e-limit" type="number" min="0" step="0.1" placeholder="0 = Unlimited"></div>
      <div class="form-group" style="max-width:90px"><label class="form-label">Unit</label><select class="form-select" id="e-unit"><option value="GB">GB</option><option value="MB">MB</option></select></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label class="form-label">Max Connections</label><input class="form-input" id="e-maxconn" type="number" min="0" placeholder="0"></div>
      <div class="form-group"><label class="form-label">Expiry Days</label><input class="form-input" id="e-expiry" type="number" min="0" placeholder="0 = Keep current"></div>
    </div>
    <div class="form-group"><label class="form-label">Tag</label><input class="form-input" id="e-tag" placeholder="e.g. VIP"></div>
    <div style="display:flex;gap:8px;margin-top:12px">
      <button class="btn btn-primary" onclick="saveEdit()" style="flex:1;justify-content:center">Save</button>
      <button class="btn btn-danger" onclick="resetTraffic()">Reset Traffic</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="addr-modal" onclick="if(event.target===this)closeModal('addr-modal')">
  <div class="modal" style="position:relative">
    <button class="modal-close" onclick="closeModal('addr-modal')">&times;</button>
    <div class="modal-title">Add Clean IP / Domain</div>
    <div class="form-group"><label class="form-label">Addresses (one per line)</label><textarea class="form-input" id="n-addr" rows="5" placeholder="8.8.8.8&#10;example.com" style="resize:vertical;font-family:'JetBrains Mono',monospace;height:auto;padding:10px 12px"></textarea></div>
    <button class="btn btn-primary" style="width:100%;justify-content:center;margin-top:4px" onclick="addAddresses()">Add All</button>
  </div>
</div>

<div class="modal-overlay" id="logs-modal" onclick="if(event.target===this)closeModal('logs-modal')">
  <div class="modal" style="max-width:560px;position:relative">
    <button class="modal-close" onclick="closeModal('logs-modal')">&times;</button>
    <div class="modal-title">Logs &amp; Connections</div>
    <div style="background:var(--surface2);border-radius:8px;padding:12px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text2);max-height:400px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;line-height:1.6" id="logs-box">Loading...</div>
    <button class="btn btn-secondary" style="width:100%;justify-content:center;margin-top:10px" onclick="openLogs()">Refresh</button>
  </div>
</div>

<div class="modal-overlay" id="config-modal" onclick="if(event.target===this)closeModal('config-modal')">
  <div class="modal" style="max-width:560px;position:relative">
    <button class="modal-close" onclick="closeModal('config-modal')">&times;</button>
    <div class="modal-title">Runtime Config</div>
    <div style="background:var(--surface2);border-radius:8px;padding:12px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text2);max-height:400px;overflow-y:auto;white-space:pre-wrap" id="config-box">Loading...</div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
var allLinks=[],curFilter='all',apiStats={},trafficChart=null;
function go(id,el){document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active')});document.getElementById('page-'+id).classList.add('active');document.querySelectorAll('.nav-item').forEach(function(n){n.classList.remove('active')});if(el)el.classList.add('active');closeSidebar();if(id==='inbounds')loadInbounds();if(id==='cleanip')loadAddresses();if(id==='domain')loadDomain()}
function toggleSidebar(){document.getElementById('sidebar').classList.toggle('open');document.getElementById('overlay').classList.toggle('show')}
function closeSidebar(){document.getElementById('sidebar').classList.remove('open');document.getElementById('overlay').classList.remove('show')}
function closeModal(id){document.getElementById(id).classList.remove('show')}
function showModal(id){document.getElementById(id).classList.add('show')}
function toast(m,e){var t=document.getElementById('toast');t.textContent=m;t.className='toast '+(e?'error':'success')+' show';setTimeout(function(){t.classList.remove('show')},3000)}
function esc(s){return String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function fmtB(b){if(!b||b===0)return '0 B';if(b>=1073741824)return(b/1073741824).toFixed(2)+' GB';if(b>=1048576)return(b/1048576).toFixed(2)+' MB';if(b>=1024)return(b/1024).toFixed(1)+' KB';return b+' B'}
function fmtL(b){if(!b||b===0)return 'Unlimited';var g=b/1073741824;return(g%1===0?g.toFixed(0):g.toFixed(1))+' GB'}

function setGauge(id,pct){pct=Math.max(0,Math.min(100,pct||0));var el=document.getElementById(id);if(el)el.setAttribute('stroke-dashoffset',(201*(1-pct/100)).toFixed(1))}

async function loadStats(){
  try{
    var r=await fetch('/api/stats');if(!r.ok)throw 0;apiStats=await r.json();
    setGauge('g-cpu',apiStats.cpuUsage);setGauge('g-ram',apiStats.ramUsage);setGauge('g-swap',apiStats.swapUsage);setGauge('g-disk',apiStats.storageUsage);
    document.getElementById('g-cpu-t').textContent=(apiStats.cpuUsage||0).toFixed(1)+'%';
    document.getElementById('g-ram-t').textContent=(apiStats.ramUsage||0).toFixed(1)+'%';
    document.getElementById('g-swap-t').textContent=(apiStats.swapUsage||0).toFixed(1)+'%';
    document.getElementById('g-disk-t').textContent=(apiStats.storageUsage||0).toFixed(1)+'%';
    var run=apiStats.xrayRunning!==false;
    document.getElementById('xray-dot').className='badge-dot '+(run?'green':'red');
    document.getElementById('xray-status-text').textContent=run?'Running':'Stopped';
    document.getElementById('s-conn').textContent=apiStats.activeConnections||0;
    document.getElementById('s-up').textContent=apiStats.uploadSpeed||'--';
    document.getElementById('s-down').textContent=apiStats.downloadSpeed||'--';
    document.getElementById('s-traffic').textContent=(apiStats.totalTrafficMb||0).toFixed(2)+' MB';
    document.getElementById('s-sent').textContent=apiStats.totalSent||'--';
    document.getElementById('s-recv').textContent=apiStats.totalReceived||'--';
    document.getElementById('s-uptime').textContent=apiStats.xrayUptime||'--';
    document.getElementById('s-tcp-udp').textContent='TCP: '+(apiStats.tcpConnections||0)+' | UDP: '+(apiStats.udpConnections||0);
    document.getElementById('s-domain').textContent=apiStats.domain||'--';
    document.getElementById('s-ipv4').textContent=apiStats.ipv4||'N/A';
    document.getElementById('s-ipv6').textContent=apiStats.ipv6||'N/A';
    document.getElementById('s-load').textContent=apiStats.systemLoad||'--';
    document.getElementById('s-ram-th').textContent=(apiStats.appRam||'--')+' / '+(apiStats.threads||'--')+' threads';
    document.getElementById('s-os-up').textContent=apiStats.uptime||'--';
    document.getElementById('pv-tag').textContent=apiStats.panelVersion||'v2.0.0';
    document.getElementById('ver-badge').textContent=apiStats.panelVersion||'v2.0.0';
    if(apiStats.telegram)document.getElementById('tg-tag').textContent=apiStats.telegram;
    var lb=document.getElementById('links-badge');if(lb)lb.textContent=apiStats.linksCount||0;
    if(document.getElementById('ib-total'))document.getElementById('ib-total').textContent=apiStats.linksCount||0;
    if(document.getElementById('ib-traffic'))document.getElementById('ib-traffic').textContent=(apiStats.totalTrafficMb||0).toFixed(2)+' MB';
    if(document.getElementById('ib-requests'))document.getElementById('ib-requests').textContent=apiStats.totalRequests||0;
    var rd=document.getElementById('rd-domain');if(rd)rd.textContent=apiStats.domain||'--';
    updateChart(apiStats.hourlyTraffic||{});
  }catch(e){}
}

var ipsVis=false;function toggleIps(){ipsVis=!ipsVis;document.querySelectorAll('.ip-val').forEach(function(el){el.classList.toggle('visible',ipsVis)})}

function initChart(){
  var ctx=document.getElementById('trafficChart');if(!ctx)return;
  var labels=[];for(var i=0;i<24;i++){var h=(new Date().getHours()-23+i+24)%24;labels.push((h<10?'0':'')+h+':00')}
  trafficChart=new Chart(ctx,{type:'bar',data:{labels:labels,datasets:[{label:'Traffic',data:new Array(24).fill(0),backgroundColor:'rgba(99,102,241,0.3)',borderColor:'#6366f1',borderWidth:1,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{color:'rgba(255,255,255,0.03)'},ticks:{color:'#64748b',font:{size:9}}},y:{grid:{color:'rgba(255,255,255,0.03)'},ticks:{color:'#64748b',font:{size:9},callback:function(v){return fmtB(v)}}}}}});
}
function updateChart(ht){
  if(!trafficChart)return;
  var data=[];for(var i=0;i<24;i++){var h=(new Date().getHours()-23+i+24)%24;var key=(h<10?'0':'')+h+':00';data.push(((ht[key]||0)/1048576))}
  trafficChart.data.datasets[0].data=data;trafficChart.update('none');
}

async function openLogs(){
  try{var r=await fetch('/api/logs');var d=await r.json();
  var out='STATUS: '+(d.running?'Running':'Stopped')+'\nTraffic: '+fmtB(d.totals.bytes)+'  |  Requests: '+d.totals.requests+'  |  Errors: '+d.totals.errors+'\n\n';
  out+='── Active connections ('+d.connections.length+') ──\n';
  if(!d.connections.length)out+='(none)\n';
  d.connections.forEach(function(c){out+=c.ip+'  '+(c.uuid||'').slice(0,8)+'...  '+fmtB(c.bytes)+'  '+(c.connected_at||'').slice(11,19)+'\n'});
  if(d.history&&d.history.length){out+='\n── Recent history ('+d.history.length+') ──\n';d.history.slice(-20).forEach(function(h){out+=(h.time||'').slice(11,19)+'  '+(h.label||'?')+'  '+h.ip+'  -> '+h.target+'\n'})}
  out+='\n── Recent errors ('+d.errors.length+') ──\n';
  if(!d.errors.length)out+='(none)\n';
  d.errors.slice().reverse().forEach(function(e){out+=(e.time||'').slice(11,19)+'  '+e.error+'\n'});
  document.getElementById('logs-box').textContent=out;showModal('logs-modal')}catch(e){toast('Failed to load logs',true)}
}
async function openConfig(){try{var r=await fetch('/api/config');var d=await r.json();document.getElementById('config-box').textContent=JSON.stringify(d,null,2);showModal('config-modal')}catch(e){toast('Failed',true)}}
function downloadBackup(){var a=document.createElement('a');a.href='/api/backup';a.download='';document.body.appendChild(a);a.click();a.remove();toast('Backup downloaded')}

/* Inbounds */
async function loadInbounds(){
  try{var r=await fetch('/api/links');if(!r.ok)throw 0;var d=await r.json();allLinks=d.links||[];filterInbounds();
  if(document.getElementById('ib-total'))document.getElementById('ib-total').textContent=allLinks.length;
  if(document.getElementById('ib-active'))document.getElementById('ib-active').textContent=allLinks.filter(function(l){return l.active}).length;
  }catch(e){document.getElementById('inbounds-tbody').innerHTML='<tr><td colspan="7" style="text-align:center;padding:32px;color:var(--text4)">Failed to load</td></tr>'}
}
function setFilter(f,el){curFilter=f;document.querySelectorAll('.chip').forEach(function(c){c.classList.remove('active')});el.classList.add('active');filterInbounds()}
function filterInbounds(){
  var q=(document.getElementById('inbound-search')?document.getElementById('inbound-search').value:'').toLowerCase();
  var filtered=allLinks;
  if(curFilter==='active')filtered=filtered.filter(function(l){return l.active});
  if(curFilter==='disabled')filtered=filtered.filter(function(l){return !l.active});
  if(curFilter==='expired')filtered=filtered.filter(function(l){return l.expired});
  if(q)filtered=filtered.filter(function(l){return l.label.toLowerCase().indexOf(q)!==-1||l.uuid.toLowerCase().indexOf(q)!==-1});
  renderInbounds(filtered);
}
function renderInbounds(links){
  var tbody=document.getElementById('inbounds-tbody');if(!links.length){tbody.innerHTML='<tr><td colspan="7" style="text-align:center;padding:32px;color:var(--text4)">No inbounds found</td></tr>';return}
  var idx=links.length;
  tbody.innerHTML=links.map(function(l){
    var u=l.used_bytes,lim=l.limit_bytes,uF=fmtB(u),lF=fmtL(lim);
    var pct=lim>0?Math.min(100,(u/lim)*100):0;
    var col=pct>90?'#ef4444':pct>70?'#f59e0b':'#6366f1';
    var i=idx--;var mc=l.max_connections||0;var cc=l.current_connections||0;
    var statusTag=l.expired?'<span class="tag tag-amber">Expired</span>':(l.active?'<span class="tag tag-green">Active</span>':'<span class="tag tag-red">Disabled</span>');
    var tag=l.tag?'<span class="tag tag-purple" style="margin-right:4px">'+esc(l.tag)+'</span>':'';
    return '<tr><td style="color:var(--text4);font-size:10px">'+i+'</td><td style="font-weight:600;color:var(--text)">'+tag+esc(l.label)+'</td><td><span class="tag tag-purple">VLESS</span></td><td><div class="usage-pill"><span class="used">'+uF+'</span><div class="bar"><div class="fill" style="width:'+pct+'%;background:'+col+'"></div></div><span class="limit">'+lF+'</span></div></td><td style="font-size:11px;font-weight:600;color:'+(mc>0&&cc>=mc?'var(--red)':'var(--text3)')+'">'+cc+'/'+(mc||'&infin;')+'</td><td>'+statusTag+'</td><td><div style="display:flex;gap:3px;align-items:center"><button class="btn-icon btn-secondary" data-uid="'+l.uuid+'" onclick="toggleInbound(this)" title="Toggle">'+(l.active?'ON':'OFF')+'</button><button class="btn-icon btn-secondary" onclick="showEditModal(\''+l.uuid+'\')" title="Edit" style="color:var(--amber)">E</button><button class="btn-icon btn-secondary" onclick="copyVless(\''+esc(l.vless_link).replace(/'/g,"\\'")+'\')" title="Copy Config">C</button><button class="btn-icon btn-secondary" onclick="copySubUrl(\''+l.uuid+'\')" title="Copy Sub URL" style="color:var(--green)">S</button><button class="btn-icon btn-danger" onclick="deleteInbound(\''+l.uuid+'\')" title="Delete">X</button></div></td></tr>';
  }).join('');
}
async function toggleInbound(el){var uid=el.dataset.uid;var link=allLinks.find(function(l){return l.uuid===uid});if(!link)return;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:!link.active})});await loadInbounds();await loadStats()}catch(e){toast('Error',true)}}
async function createInbound(){
  var label=document.getElementById('n-label').value.trim();if(!label){toast('Name required',true);return}
  if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){toast('Invalid name',true);return}
  var val=parseFloat(document.getElementById('n-limit').value)||0;
  var unit=document.getElementById('n-unit').value;
  var mc=parseInt(document.getElementById('n-maxconn').value)||0;
  var exp=parseInt(document.getElementById('n-expiry').value)||0;
  var tag=document.getElementById('n-tag').value.trim();
  try{var r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:label,limit_value:val,limit_unit:unit,max_connections:mc,expiry_days:exp,tag:tag})});
  if(!r.ok){var d=await r.json().catch(function(){return{}});throw new Error(d.detail||'Error')}
  toast('Inbound created');document.getElementById('n-label').value='';document.getElementById('n-limit').value='';document.getElementById('n-maxconn').value='';document.getElementById('n-expiry').value='';document.getElementById('n-tag').value='';closeModal('add-modal');await loadInbounds();await loadStats()}catch(e){toast(e.message,true)}
}
async function deleteInbound(uid){if(!confirm('Delete this inbound?'))return;try{await fetch('/api/links/'+uid,{method:'DELETE'});toast('Deleted');await loadInbounds();await loadStats()}catch(e){toast('Error',true)}}
function showEditModal(uid){var l=allLinks.find(function(x){return x.uuid===uid});if(!l)return;document.getElementById('edit-uid').value=uid;document.getElementById('e-name').value=l.label;document.getElementById('e-limit').value=l.limit_bytes>0?(l.limit_bytes/1073741824).toFixed(2):'';document.getElementById('e-unit').value='GB';document.getElementById('e-maxconn').value=l.max_connections>0?l.max_connections:'';document.getElementById('e-expiry').value='';document.getElementById('e-tag').value=l.tag||'';document.getElementById('edit-title').textContent='Edit: '+l.label;showModal('edit-modal')}
async function saveEdit(){var uid=document.getElementById('edit-uid').value;var val=parseFloat(document.getElementById('e-limit').value)||0;var unit=document.getElementById('e-unit').value;var mc=parseInt(document.getElementById('e-maxconn').value)||0;var exp=parseInt(document.getElementById('e-expiry').value)||0;var tag=document.getElementById('e-tag').value.trim();var body={limit_value:val,limit_unit:unit,max_connections:mc,tag:tag};if(exp>0)body.expiry_days=exp;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast('Updated');closeModal('edit-modal');await loadInbounds()}catch(e){toast('Error',true)}}
async function resetTraffic(){var uid=document.getElementById('edit-uid').value;if(!confirm('Reset traffic?'))return;try{await fetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('Traffic reset');await loadInbounds()}catch(e){toast('Error',true)}}
function copyVless(t){navigator.clipboard.writeText(t).then(function(){toast('Config copied')}).catch(function(){toast('Copy failed',true)})}
async function copySubUrl(uid){var url='https://'+location.host+'/sub/'+uid;navigator.clipboard.writeText(url).then(function(){toast('Sub URL copied')}).catch(function(){toast('Copy failed',true)})}

/* Addresses */
var allAddrs=[];
async function loadAddresses(){try{var r=await fetch('/api/addresses');if(!r.ok)throw 0;var d=await r.json();allAddrs=d.addresses||[];renderAddrs()}catch(e){}}
function renderAddrs(){var el=document.getElementById('address-list');if(!allAddrs.length){el.innerHTML='<div style="color:var(--text4);font-size:12px;padding:8px 0">No addresses added</div>';return}
el.innerHTML=allAddrs.map(function(a,i){return '<div class="addr-item"><span>'+esc(a)+'</span><button class="btn btn-danger btn-sm" onclick="delAddr('+i+')">Remove</button></div>'}).join('')}
async function addAddresses(){var text=document.getElementById('n-addr').value.trim();if(!text){toast('Enter address',true);return}var lines=text.split('\n').map(function(l){return l.trim()}).filter(function(l){return l});var added=0,errors=0;for(var i=0;i<lines.length;i++){var addr=lines[i];if(!/^[a-zA-Z0-9\-_. ]+$/.test(addr)){errors++;continue}try{var r=await fetch('/api/addresses',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:addr})});if(r.ok)added++;else errors++}catch(e){errors++}}if(added>0)toast('Added '+added+' address(es)');if(errors>0)toast(errors+' failed',true);if(added>0){closeModal('addr-modal');await loadAddresses()}}
async function delAddr(i){if(!confirm('Remove this address?'))return;try{var r=await fetch('/api/addresses/'+i,{method:'DELETE'});if(!r.ok)throw 0;toast('Removed');await loadAddresses()}catch(e){toast('Error',true)}}

/* Domain */
var curDomain='';
async function loadDomain(){try{var r=await fetch('/api/domain');if(!r.ok)throw 0;var d=await r.json();curDomain=d.domain||'';var rd=document.getElementById('rd-domain');if(rd)rd.textContent=apiStats.domain||location.host;var dv=document.getElementById('dv-domain');var cb=document.getElementById('domain-clear-btn');if(curDomain){dv.textContent=curDomain;dv.style.color='var(--accent)';if(cb)cb.style.display=''}else{dv.textContent=(apiStats.domain||location.host)+' (default)';dv.style.color='var(--text3)';if(cb)cb.style.display='none'}}catch(e){}}
async function saveDomain(){var d=document.getElementById('domain-input').value.trim();if(!d){toast('Enter domain',true);return}try{var r=await fetch('/api/domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:d})});if(!r.ok){var j=await r.json().catch(function(){return{}});throw new Error(j.detail||'Error')}toast('Domain saved');document.getElementById('domain-input').value='';await loadDomain()}catch(e){toast(e.message,true)}}
async function clearDomain(){try{await fetch('/api/domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:''})});toast('Domain cleared');await loadDomain()}catch(e){toast('Error',true)}}

/* Panel Builder */
async function deployPanel(){
  var token=document.getElementById('pb-token').value.trim();var space=document.getElementById('pb-space').value.trim();var user=document.getElementById('pb-user').value.trim();var pass=document.getElementById('pb-pass').value;
  if(!token){toast('HF token required',true);return}if(!space){toast('Space name required',true);return}if(pass.length<4){toast('Password min 4 chars',true);return}
  var res=document.getElementById('pb-result');res.style.display='block';res.innerHTML='<div style="color:var(--text3);font-size:12px">Deploying... please wait</div>';
  try{var r=await fetch('/api/panel-builder/deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hf_token:token,space_name:space,admin_username:user,admin_password:pass})});
  if(!r.ok){var d=await r.json().catch(function(){return{}});throw new Error(d.detail||'Deploy failed')}
  var d=await r.json();res.innerHTML='<div style="color:var(--green);font-size:13px;font-weight:600">Panel deployed successfully!</div><div style="margin-top:8px"><a href="'+esc(d.space_url)+'" target="_blank" style="color:var(--accent);font-size:12px">'+esc(d.space_url)+'</a></div><div style="margin-top:4px"><a href="'+esc(d.app_url)+'/dashboard" target="_blank" style="color:var(--accent2);font-size:12px">'+esc(d.app_url)+'/dashboard</a></div>';toast('Panel deployed!')}catch(e){res.innerHTML='<div style="color:var(--red);font-size:12px">'+esc(e.message)+'</div>';toast(e.message,true)}
}

/* Settings */
async function changePassword(){var cur=document.getElementById('cur-pw').value;var nw=document.getElementById('new-pw').value;var cf=document.getElementById('cfm-pw').value;if(!cur||!nw||!cf){toast('Fill all fields',true);return}if(nw!==cf){toast('Passwords dont match',true);return}if(nw.length<4){toast('Min 4 characters',true);return}try{var r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});if(!r.ok){var d=await r.json().catch(function(){return{}});throw new Error(d.detail||'Error')}toast('Password updated');document.getElementById('cur-pw').value='';document.getElementById('new-pw').value='';document.getElementById('cfm-pw').value=''}catch(e){toast(e.message,true)}}
async function doLogout(){await fetch('/api/logout',{method:'POST'});location.href='/login'}

/* Init */
initChart();loadStats();loadInbounds();
setInterval(loadStats,5000);setInterval(loadInbounds,15000);
</script>
</body>
</html>"""

#  USF Panel v2.0.0 — Routes & Main
# ============================================================

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/inbounds", response_class=HTMLResponse)
async def inbounds_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return RedirectResponse(url="/dashboard")

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return RedirectResponse(url="/dashboard")

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=CONFIG["port"],
        loop="uvloop" if _HAS_UVLOOP else "asyncio",
        http="httptools" if _HAS_UVLOOP else "h11",
        ws="websockets",
        log_level="info",
        access_log=False,
        timeout_keep_alive=75,
    )
