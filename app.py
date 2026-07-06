import asyncio, json, os, hashlib, secrets, time, re, socket, sqlite3, uuid, threading, psutil, struct
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn, httpx, logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("USF")

app = FastAPI(title="USF", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ── Config ────────────────────────────────────────────────────────────────────
PORT = int(os.environ.get("PORT", 7860))
SECRET = os.environ.get("SECRET_KEY", "usf-secret")
PANEL_VER = "v2.0.0"
DB_PATH = os.environ.get("DB_PATH", "/tmp/usf.db")
RELAY_BUF = 512 * 1024

# ── State ─────────────────────────────────────────────────────────────────────
LINKS = {}
LINKS_LOCK = asyncio.Lock()
CUSTOM_ADDRESSES = ["amazonaws.com"]
CUSTOM_DOMAIN = ""
SESSIONS = {}
SESSIONS_LOCK = asyncio.Lock()
connections = {}
connection_sockets = {}
link_ip_map = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs = deque(maxlen=50)
hourly_traffic = defaultdict(int)
SERVICE_RUNNING = True
SERVICE_STARTED = time.time()
SESSION_COOKIE = "usf_session"
SESSION_TTL = 86400 * 7
http_client = None
_net_base = {"s": 0, "r": 0, "t": time.time()}

AUTH = {
    "username": os.environ.get("ADMIN_USERNAME", "admin"),
    "password_hash": hashlib.sha256(f"{os.environ.get('ADMIN_PASSWORD', 'admin')}{SECRET}".encode()).hexdigest(),
}

# ── Database ──────────────────────────────────────────────────────────────────
_db_lock = threading.Lock()

def db_init():
    try:
        with _db_lock, sqlite3.connect(DB_PATH) as c:
            c.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)")
            c.commit()
    except Exception as e:
        logger.warning(f"DB init failed: {e}")

def db_set(k, v):
    try:
        with _db_lock, sqlite3.connect(DB_PATH) as c:
            c.execute("INSERT OR REPLACE INTO kv (key, value, updated_at) VALUES (?,?,?)", (k, v, datetime.now().isoformat()))
            c.commit()
    except: pass

def db_get(k, default=None):
    try:
        with _db_lock, sqlite3.connect(DB_PATH) as c:
            r = c.execute("SELECT value FROM kv WHERE key=?", (k,)).fetchone()
            return r[0] if r else default
    except: return default

def db_del(k):
    try:
        with _db_lock, sqlite3.connect(DB_PATH) as c:
            c.execute("DELETE FROM kv WHERE key=?", (k,))
            c.commit()
    except: pass

# ── Auth helpers ──────────────────────────────────────────────────────────────
def hash_pw(pw):
    return hashlib.sha256(f"{pw}{SECRET}".encode()).hexdigest()

async def make_session():
    t = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK: SESSIONS[t] = time.time() + SESSION_TTL
    return t

async def valid_session(t):
    if not t: return False
    async with SESSIONS_LOCK:
        e = SESSIONS.get(t)
        if not e or e < time.time():
            SESSIONS.pop(t, None)
            return False
        return True

async def kill_session(t):
    if t:
        async with SESSIONS_LOCK: SESSIONS.pop(t, None)

async def require_auth(req: Request):
    if not await valid_session(req.cookies.get(SESSION_COOKIE)):
        raise HTTPException(401, "unauthorized")

# ── Utility ───────────────────────────────────────────────────────────────────
def get_domain():
    d = os.environ.get("SPACE_HOST", "")
    if d:
        return d.replace("https://", "").replace("http://", "").rstrip("/")
    a = os.environ.get("SPACE_AUTHOR_NAME", "")
    n = os.environ.get("SPACE_NAME", "")
    if a and n:
        return f"{a}-{n}.hf.space"
    return "localhost"

def gen_uuid(seed=None):
    if seed is None:
        return str(uuid.uuid4())
    h = hashlib.sha256(f"{seed}{SECRET}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def gen_vless_link(uid, remark="USF", address=None):
    domain = CUSTOM_DOMAIN or get_domain()
    addr = address or domain
    path = f"/ws/{uid}"
    params = "&".join(f"{k}={quote(str(v))}" for k, v in {
        "encryption": "none", "security": "tls", "type": "ws",
        "host": domain, "path": path, "sni": domain,
        "fp": "chrome", "alpn": "http/1.1",
    }.items())
    return f"vless://{uid}@{addr}:443?{params}#{quote(remark)}"

def fmt_bytes(b):
    if b >= 1073741824: return f"{b/1073741824:.2f} GB"
    if b >= 1048576: return f"{b/1048576:.2f} MB"
    if b >= 1024: return f"{b/1024:.1f} KB"
    return f"{b} B"

def fmt_speed(bps):
    if bps >= 1048576: return f"{bps/1048576:.2f} MB/s"
    if bps >= 1024: return f"{bps/1024:.2f} KB/s"
    return f"{bps:.0f} B/s"

def parse_size(v, u):
    u = u.upper()
    if u == "GB": return int(v * 1073741824)
    if u == "MB": return int(v * 1048576)
    if u == "TB": return int(v * 1099511627776)
    return int(v)

def compute_expiry(days):
    try: days = float(days or 0)
    except: days = 0
    if days <= 0: return ""
    return (datetime.now() + timedelta(days=days)).isoformat()

def is_expired(link):
    e = link.get("expiry") if isinstance(link, dict) else None
    if not e: return False
    try: return datetime.now() >= datetime.fromisoformat(e)
    except: return False

def expiry_epoch(link):
    e = link.get("expiry") if isinstance(link, dict) else None
    if not e: return 0
    try: return int(datetime.fromisoformat(e).timestamp())
    except: return 0

def uptime_str():
    s = int(time.time() - stats["start_time"])
    h, m = s // 3600, (s % 3600) // 60
    return f"{h:02d}:{m:02d}:{s%60:02d}"

def get_net_speed():
    global _net_base
    try:
        nc = psutil.net_io_counters()
        now = time.time()
        dt = max(now - _net_base["t"], 0.1)
        up = (nc.bytes_sent - _net_base["s"]) / dt
        dn = (nc.bytes_recv - _net_base["r"]) / dt
        _net_base = {"s": nc.bytes_sent, "r": nc.bytes_recv, "t": now}
        return nc.bytes_sent, nc.bytes_recv, up, dn
    except: return 0, 0, 0, 0

def get_client_ip(ws):
    f = ws.headers.get("x-forwarded-for")
    if f: return f.split(",")[0].strip()
    return ws.client.host if ws.client else "?"

def count_conns(uid):
    return len(link_ip_map.get(uid, set()))

def remove_ip(uid, ip):
    if uid in link_ip_map:
        link_ip_map[uid].discard(ip)
        if not link_ip_map[uid]: link_ip_map.pop(uid, None)

async def close_conns(uid):
    for cid in [c for c, i in connections.items() if i.get("uuid") == uid]:
        ws = connection_sockets.pop(cid, None)
        if ws:
            try: await ws.close(code=1000, reason="deleted")
            except: pass
        connections.pop(cid, None)
    link_ip_map.pop(uid, None)

async def check_quota(uid, n):
    async with LINKS_LOCK:
        lk = LINKS.get(uid)
        if not lk or not lk["active"] or is_expired(lk): return False
        if lk["limit_bytes"] == 0: return True
        return (lk["used_bytes"] + n) <= lk["limit_bytes"]

async def add_usage(uid, n):
    async with LINKS_LOCK:
        if uid in LINKS: LINKS[uid]["used_bytes"] += n

# ── Periodic save ─────────────────────────────────────────────────────────────
async def periodic_save():
    while True:
        await asyncio.sleep(30)
        try:
            async with LINKS_LOCK: db_set("links", json.dumps(LINKS, ensure_ascii=False))
            db_set("addresses", json.dumps(CUSTOM_ADDRESSES))
            db_set("domain", CUSTOM_DOMAIN)
            db_set("auth_hash", AUTH["password_hash"])
        except Exception as e:
            logger.warning(f"save failed: {e}")

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            d = get_domain()
            if d and d != "localhost":
                async with httpx.AsyncClient(timeout=10) as c: await c.get(f"https://{d}/health")
        except: pass

# ── Startup / Shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global http_client, _net_base, CUSTOM_DOMAIN, CUSTOM_ADDRESSES, AUTH
    db_init()
    # Load persisted state
    saved = db_get("links")
    if saved:
        try:
            async with LINKS_LOCK: LINKS.update(json.loads(saved))
            logger.info(f"Loaded {len(LINKS)} links")
        except: pass
    sa = db_get("addresses")
    if sa:
        try: CUSTOM_ADDRESSES = json.loads(sa)
        except: pass
    sd = db_get("domain")
    if sd is not None: CUSTOM_DOMAIN = sd
    sp = db_get("auth_hash")
    if sp: AUTH["password_hash"] = sp

    # Ensure at least one default link
    async with LINKS_LOCK:
        if not LINKS:
            uid = gen_uuid()
            LINKS[uid] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "max_connections": 0, "created_at": datetime.now().isoformat(), "active": True, "expiry": ""}

    http_client = httpx.AsyncClient(limits=httpx.Limits(max_connections=500, max_keepalive_connections=100), timeout=httpx.Timeout(30, connect=10), follow_redirects=True)
    try:
        nc = psutil.net_io_counters()
        _net_base = {"s": nc.bytes_sent, "r": nc.bytes_recv, "t": time.time()}
    except: pass
    asyncio.create_task(periodic_save())
    asyncio.create_task(keep_alive())
    logger.info(f"USF started on port {PORT}")

@app.on_event("shutdown")
async def shutdown():
    try:
        async with LINKS_LOCK: db_set("links", json.dumps(LINKS, ensure_ascii=False))
        db_set("addresses", json.dumps(CUSTOM_ADDRESSES))
        db_set("domain", CUSTOM_DOMAIN)
        db_set("auth_hash", AUTH["password_hash"])
    except: pass
    if http_client: await http_client.aclose()

# ══════════════════════════════════════════════════════════════════════════════
#  VLESS PROXY
# ══════════════════════════════════════════════════════════════════════════════

def parse_vless_header(data: bytes):
    """Parse VLESS header: version(1) + uuid(16) + addon_len(1) + addon + cmd(1) + addr_type(1) + addr + port(2) + payload"""
    if len(data) < 24:
        raise ValueError(f"header too small: {len(data)} bytes")
    pos = 0
    pos += 1      # version
    pos += 16     # uuid
    addon_len = data[pos]; pos += 1; pos += addon_len  # addon
    cmd = data[pos]; pos += 1  # command
    atype = data[pos]; pos += 1  # address type
    if atype == 1:  # IPv4
        addr = ".".join(str(b) for b in data[pos:pos+4]); pos += 4
    elif atype == 2:  # Domain
        dlen = data[pos]; pos += 1
        addr = data[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif atype == 3:  # IPv6
        a = data[pos:pos+16]; pos += 16
        addr = ":".join(f"{a[i]:02x}{a[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr_type: {atype}")
    port = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2
    return cmd, addr, port, data[pos:]

async def relay_ws_tcp(ws: WebSocket, writer, cid, uid):
    """WebSocket -> TCP"""
    try:
        while True:
            data = await ws.receive_bytes()
            if not data: continue
            sz = len(data)
            if not await check_quota(uid, sz):
                await ws.close(code=1008, reason="quota"); break
            stats["total_bytes"] += sz; stats["total_requests"] += 1
            if cid in connections: connections[cid]["bytes"] += sz
            hourly_traffic[datetime.now().strftime("%H:00")] += sz
            await add_usage(uid, sz)
            writer.write(data)
            await writer.drain()
    except WebSocketDisconnect: pass
    except Exception: pass
    finally:
        try: writer.write_eof()
        except: pass

async def relay_tcp_ws(ws: WebSocket, reader, cid, uid):
    """TCP -> WebSocket (raw bytes, no extra header)"""
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            sz = len(data)
            if not await check_quota(uid, sz):
                await ws.close(code=1008, reason="quota"); break
            stats["total_bytes"] += sz
            if cid in connections: connections[cid]["bytes"] += sz
            hourly_traffic[datetime.now().strftime("%H:00")] += sz
            await add_usage(uid, sz)
            await ws.send_bytes(data)
    except Exception: pass

@app.websocket("/ws/{uid}")
async def ws_tunnel(ws: WebSocket, uid: str):
    await ws.accept()
    writer = None
    cid = None
    cip = get_client_ip(ws)
    try:
        if not SERVICE_RUNNING:
            await ws.close(code=1012, reason="stopped"); return
        async with LINKS_LOCK:
            lk = LINKS.get(uid)
            if not lk or not lk["active"]:
                logger.warning(f"WS reject: uuid={uid[:8]} not found/disabled ip={cip}")
                await ws.close(code=1008, reason="not found"); return
            if is_expired(lk):
                await ws.close(code=1008, reason="expired"); return
            mc = lk.get("max_connections", 0)
        if mc > 0:
            if cip not in link_ip_map.get(uid, set()) and count_conns(uid) >= mc:
                await ws.close(code=1008, reason="limit"); return
        # Receive first message (VLESS header + payload)
        first = await asyncio.wait_for(ws.receive_bytes(), timeout=30)
        if not first: return
        cmd, addr, port, payload = parse_vless_header(first)
        logger.info(f"WS: {cip} -> {addr}:{port} cmd={cmd}")
        # Connect to target
        reader, writer = await asyncio.wait_for(asyncio.open_connection(addr, port), timeout=15)
        # TCP optimizations
        try:
            sock = writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512*1024)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512*1024)
        except: pass
        # Register connection
        cid = secrets.token_urlsafe(8)
        connections[cid] = {"uuid": uid, "ip": cip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[cid] = ws
        link_ip_map[uid].add(cip)
        # Count first message stats
        sz = len(first)
        stats["total_bytes"] += sz; stats["total_requests"] += 1
        connections[cid]["bytes"] += sz
        hourly_traffic[datetime.now().strftime("%H:00")] += sz
        await add_usage(uid, sz)
        # Send payload
        if payload:
            writer.write(payload)
            await writer.drain()
        # Bidirectional relay — clean shutdown, no abrupt cancel
        t1 = asyncio.create_task(relay_ws_tcp(ws, writer, cid, uid))
        t2 = asyncio.create_task(relay_tcp_ws(ws, reader, cid, uid))
        done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        # Close the other direction so the remaining task finishes naturally
        if t1 in done:
            try: writer.close()
            except: pass
        if t2 in done:
            try: await ws.close(code=1000, reason="relay done")
            except: pass
        await asyncio.gather(*pending, return_exceptions=True)
    except WebSocketDisconnect:
        logger.info(f"WS disconnect: {cip}")
    except Exception as e:
        stats["total_errors"] += 1
        logger.error(f"WS error: {e}")
        error_logs.append({"error": str(e), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        if cid:
            info = connections.pop(cid, None)
            connection_sockets.pop(cid, None)
            if info:
                u, ip = info.get("uuid"), info.get("ip")
                if u and ip:
                    if not any(c.get("uuid") == u and c.get("ip") == ip for c in connections.values()):
                        remove_ip(u, ip)

# ══════════════════════════════════════════════════════════════════════════════
#  API ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/")
async def root(req: Request):
    if await valid_session(req.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")

@app.get("/health")
async def health():
    return {"status": "ok", "conns": len(connections), "uptime": uptime_str()}

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.post("/api/login")
async def api_login(req: Request):
    body = await req.json()
    u, p = str(body.get("username") or ""), str(body.get("password") or "")
    if u and u != AUTH["username"]:
        raise HTTPException(401, "invalid credentials")
    if hash_pw(p) != AUTH["password_hash"]:
        raise HTTPException(401, "invalid credentials")
    token = await make_session()
    is_https = req.url.scheme == "https"
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/", secure=is_https)
    return resp

@app.post("/api/logout")
async def api_logout(req: Request):
    await kill_session(req.cookies.get(SESSION_COOKIE))
    r = JSONResponse({"ok": True})
    r.delete_cookie(SESSION_COOKIE, path="/")
    return r

@app.get("/api/me")
async def api_me(req: Request):
    return {"auth": await valid_session(req.cookies.get(SESSION_COOKIE))}

@app.post("/api/change-password")
async def api_change_pw(req: Request, _=Depends(require_auth)):
    b = await req.json()
    if hash_pw(b.get("current", "")) != AUTH["password_hash"]:
        raise HTTPException(400, "wrong password")
    nw = b.get("new", "")
    if len(nw) < 4: raise HTTPException(400, "too short")
    AUTH["password_hash"] = hash_pw(nw)
    async with SESSIONS_LOCK:
        t = req.cookies.get(SESSION_COOKIE)
        SESSIONS.clear()
        if t: SESSIONS[t] = time.time() + SESSION_TTL
    return {"ok": True}

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def api_stats(_=Depends(require_auth)):
    cpu = psutil.cpu_percent(interval=0.1)
    vm = psutil.virtual_memory()
    ts, tr, up, dn = get_net_speed()
    try:
        sw = psutil.swap_memory()
        disk = psutil.disk_usage("/")
    except: sw = None; disk = None
    su = int(time.time() - SERVICE_STARTED)
    su_s = f"{su//86400}d {(su%86400)//3600}h" if su >= 86400 else f"{su//3600}h {(su%3600)//60}m" if su >= 3600 else f"{su//60}m"
    return {
        "cpu": round(cpu, 1), "ram": round(vm.percent, 1),
        "ramUsed": f"{vm.used/1048576:.0f} MB", "ramTotal": f"{vm.total/1048576:.0f} MB",
        "upload": fmt_speed(up), "download": fmt_speed(dn),
        "totalSent": fmt_bytes(ts), "totalRecv": fmt_bytes(tr),
        "uptime": uptime_str(), "serviceUptime": su_s,
        "activeConns": len(connections), "linksCount": len(LINKS),
        "totalTraffic": round(stats["total_bytes"]/1048576, 2),
        "totalRequests": stats["total_requests"], "totalErrors": stats["total_errors"],
        "domain": get_domain(), "panelVer": PANEL_VER,
        "swap": f"{sw.percent:.0f}%" if sw else "N/A",
        "disk": f"{disk.percent:.0f}%" if disk else "N/A",
        "recentErrors": list(error_logs)[-5:],
        "running": SERVICE_RUNNING,
    }

@app.post("/api/service/stop")
async def svc_stop(_=Depends(require_auth)):
    global SERVICE_RUNNING
    SERVICE_RUNNING = False
    for ws in connection_sockets.values():
        try: await ws.close(code=1012)
        except: pass
    connections.clear(); connection_sockets.clear(); link_ip_map.clear()
    return {"ok": True}

@app.post("/api/service/restart")
async def svc_restart(_=Depends(require_auth)):
    global SERVICE_RUNNING, SERVICE_STARTED
    await svc_stop(None)
    SERVICE_RUNNING = True; SERVICE_STARTED = time.time()
    return {"ok": True}

@app.get("/api/logs")
async def api_logs(_=Depends(require_auth)):
    return {
        "errors": list(error_logs)[-50:],
        "connections": [{"id": c, "uuid": i.get("uuid"), "ip": i.get("ip"), "bytes": i.get("bytes", 0), "at": i.get("connected_at")} for c, i in connections.items()],
        "totals": {"bytes": stats["total_bytes"], "requests": stats["total_requests"], "errors": stats["total_errors"]},
    }

# ── Links / Inbounds ─────────────────────────────────────────────────────────
@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    async with LINKS_LOCK:
        result = []
        for uid, d in LINKS.items():
            result.append({
                "uuid": uid, "label": d["label"],
                "limit_bytes": d["limit_bytes"], "used_bytes": d["used_bytes"],
                "max_connections": d.get("max_connections", 0),
                "active": d["active"], "expiry": d.get("expiry", ""),
                "expired": is_expired(d), "created_at": d["created_at"],
                "current_connections": count_conns(uid),
                "vless_link": gen_vless_link(uid, f"USF-{d['label']}"),
                "sub_url": f"https://{get_domain()}/sub/{uid}",
            })
        result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.post("/api/links")
async def create_link(req: Request, _=Depends(require_auth)):
    b = await req.json()
    label = (b.get("label") or "New").strip()[:60]
    if not label or not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(400, "invalid label")
    async with LINKS_LOCK:
        if any(d["label"].lower() == label.lower() for d in LINKS.values()):
            raise HTTPException(400, "duplicate name")
    lv = float(b.get("limit_value") or 0)
    lu = b.get("limit_unit") or "GB"
    lb = 0 if lv <= 0 else parse_size(lv, lu)
    mc = max(0, int(b.get("max_connections") or 0))
    exp = compute_expiry(b.get("expiry_days"))
    uid = gen_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {"label": label, "limit_bytes": lb, "used_bytes": 0, "max_connections": mc, "created_at": datetime.now().isoformat(), "active": True, "expiry": exp}
    return {"uuid": uid, "label": label, "vless_link": gen_vless_link(uid, f"USF-{label}")}

@app.patch("/api/links/{uid}")
async def update_link(uid: str, req: Request, _=Depends(require_auth)):
    b = await req.json()
    async with LINKS_LOCK:
        if uid not in LINKS: raise HTTPException(404, "not found")
        if "active" in b: LINKS[uid]["active"] = bool(b["active"])
        if "label" in b: LINKS[uid]["label"] = str(b["label"])[:60]
        if "limit_value" in b:
            lv = float(b.get("limit_value") or 0)
            lu = b.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if lv <= 0 else parse_size(lv, lu)
        if b.get("reset_usage"): LINKS[uid]["used_bytes"] = 0
        if "expiry_days" in b: LINKS[uid]["expiry"] = compute_expiry(b.get("expiry_days"))
        if "max_connections" in b: LINKS[uid]["max_connections"] = max(0, int(b["max_connections"] or 0))
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK: LINKS.pop(uid, None)
    await close_conns(uid)
    return {"ok": True}

@app.get("/api/links/{uid}/sub")
async def get_link_sub(uid: str, _=Depends(require_auth)):
    import base64
    async with LINKS_LOCK:
        lk = LINKS.get(uid)
        if not lk: raise HTTPException(404, "not found")
    vl = gen_vless_link(uid, f"USF-{lk['label']}")
    sub = f"# USF Subscription\n# {lk['label']}\n{vl}"
    return {"vless": vl, "sub_b64": base64.b64encode(sub.encode()).decode(), "label": lk["label"]}

# ── Domain ────────────────────────────────────────────────────────────────────
@app.get("/api/domain")
async def get_dom(_=Depends(require_auth)):
    return {"domain": CUSTOM_DOMAIN}

@app.post("/api/domain")
async def set_dom(req: Request, _=Depends(require_auth)):
    global CUSTOM_DOMAIN
    d = (await req.json()).get("domain", "").strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    if d and not re.match(r'^[a-z0-9\-_.]+$', d):
        raise HTTPException(400, "invalid domain")
    CUSTOM_DOMAIN = d
    return {"ok": True}

# ── Addresses ─────────────────────────────────────────────────────────────────
@app.get("/api/addresses")
async def list_addrs(_=Depends(require_auth)):
    return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
async def add_addr(req: Request, _=Depends(require_auth)):
    a = (await req.json()).get("address", "").strip()
    if not a or not re.match(r'^[a-zA-Z0-9\-_. ]+$', a):
        raise HTTPException(400, "invalid")
    if a in CUSTOM_ADDRESSES: raise HTTPException(400, "exists")
    CUSTOM_ADDRESSES.append(a)
    return {"ok": True}

@app.delete("/api/addresses/{idx}")
async def del_addr(idx: int, _=Depends(require_auth)):
    if 0 <= idx < len(CUSTOM_ADDRESSES): CUSTOM_ADDRESSES.pop(idx)
    else: raise HTTPException(404, "not found")
    return {"ok": True}

# ── Backup ────────────────────────────────────────────────────────────────────
@app.get("/api/backup")
async def download_backup(_=Depends(require_auth)):
    async with LINKS_LOCK: links = {u: dict(d) for u, d in LINKS.items()}
    data = json.dumps({"panel": "USF", "ver": PANEL_VER, "at": datetime.now().isoformat(), "domain": CUSTOM_DOMAIN, "addresses": list(CUSTOM_ADDRESSES), "auth_hash": AUTH["password_hash"], "links": links}, indent=2)
    fname = f"USF-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    return Response(content=data, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{fname}"'})

@app.post("/api/restore")
async def restore_backup(req: Request, _=Depends(require_auth)):
    global CUSTOM_DOMAIN
    b = await req.json()
    links = b.get("links")
    if not isinstance(links, dict): raise HTTPException(400, "invalid backup")
    async with LINKS_LOCK:
        LINKS.clear()
        for uid, d in links.items():
            if not isinstance(d, dict): continue
            LINKS[uid] = {"label": str(d.get("label", "Restored"))[:60], "limit_bytes": int(d.get("limit_bytes", 0) or 0), "used_bytes": int(d.get("used_bytes", 0) or 0), "max_connections": int(d.get("max_connections", 0) or 0), "created_at": d.get("created_at", datetime.now().isoformat()), "active": bool(d.get("active", True)), "expiry": d.get("expiry", "")}
    if isinstance(b.get("addresses"), list):
        CUSTOM_ADDRESSES.clear()
        for a in b["addresses"]:
            if isinstance(a, str) and a: CUSTOM_ADDRESSES.append(a)
    if isinstance(b.get("domain"), str): CUSTOM_DOMAIN = b["domain"]
    return {"ok": True, "restored": len(LINKS)}

# ── Subscription (public) ────────────────────────────────────────────────────
@app.get("/sub/{uid}")
async def sub_endpoint(uid: str):
    import base64
    async with LINKS_LOCK:
        lk = LINKS.get(uid)
        if not lk: raise HTTPException(404, "not found")
        if not lk["active"]: raise HTTPException(403, "disabled")
        if is_expired(lk): raise HTTPException(403, "expired")
    links_list = [gen_vless_link(uid, f"USF-{lk['label']}")]
    for i, a in enumerate(CUSTOM_ADDRESSES):
        links_list.append(gen_vless_link(uid, f"USF-{lk['label']}-IP{i+1}", address=a))
    encoded = base64.b64encode("\n".join(links_list).encode()).decode()
    return Response(content=encoded, media_type="text/plain", headers={
        "Content-Disposition": 'attachment; filename="sub.txt"',
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={lk['used_bytes']}; download=0; total={lk['limit_bytes']}; expire={expiry_epoch(lk)}",
        "profile-title": f"USF-{lk['label']}",
    })

# ══════════════════════════════════════════════════════════════════════════════
#  HTML PAGES
# ══════════════════════════════════════════════════════════════════════════════

LOGIN_HTML = r"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>USF - Login</title><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0d1b2a;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem}
#box{background:#151f31;border-radius:1.5rem;padding:2.5rem 2rem;width:100%;max-width:380px;animation:up .4s ease}
@keyframes up{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}
h2{text-align:center;color:#b0bec5;font-size:1.8rem;margin-bottom:1.5rem;font-weight:700}
.field{margin-bottom:14px}
.field input{width:100%;background:#1e2d42;border:1.5px solid #1e2d42;border-radius:30px;padding:14px 16px;color:#fff;font-size:14px;outline:none;transition:border .2s}
.field input:focus{border-color:#008771}
.field input::placeholder{color:#4a6080}
button{width:100%;padding:14px;background:linear-gradient(135deg,#007a68,#008771);border:none;border-radius:30px;color:#fff;font-size:15px;font-weight:600;cursor:pointer;transition:opacity .2s}
button:hover{opacity:.9}
.err{color:#ef4444;text-align:center;font-size:13px;margin-top:10px;display:none}
</style></head><body>
<div id="box">
<h2>USF</h2>
<form id="f">
<div class="field"><input id="u" placeholder="Username" value="admin" autocomplete="username"></div>
<div class="field"><input id="p" type="password" placeholder="Password" autocomplete="current-password"></div>
<button type="submit">Log In</button>
<div class="err" id="err"></div>
</form>
</div>
<script>
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const err=document.getElementById('err');err.style.display='none';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
    if(!r.ok){const d=await r.json().catch(()=>({}));err.textContent=d.detail||'Login failed';err.style.display='block';return}
    window.location.href='/dashboard';
  }catch(e){err.textContent='Connection error';err.style.display='block'}
};
</script></body></html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>USF - Dashboard</title>
<style>
:root{--bg:#0b1120;--surface:#131c2e;--surface2:#192438;--border:#1e2d45;--text:#e2e8f0;--text2:#94a3b8;--accent:#00d4aa;--accent2:#00b894;--danger:#ef4444;--warn:#f59e0b;--radius:10px}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#2a3a55;border-radius:3px}

/* Layout */
.layout{display:flex;min-height:100vh}
.sidebar{width:220px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;bottom:0;z-index:50;transition:transform .3s}
.sidebar .brand{padding:20px 16px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.sidebar .brand span{font-size:16px;font-weight:700;color:#fff}
.sidebar .brand small{font-size:10px;color:#475569;margin-left:auto}
.sidebar nav{flex:1;padding:8px}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:8px;color:var(--text2);font-size:13px;cursor:pointer;transition:all .15s;border:none;background:none;width:100%;text-align:left;margin:2px 0;font-family:inherit}
.nav-item:hover{background:rgba(0,212,170,.06);color:var(--text)}
.nav-item.active{background:rgba(0,212,170,.1);color:var(--accent);font-weight:600}
.nav-item svg{width:18px;height:18px;flex-shrink:0}
.sidebar .footer{padding:12px;border-top:1px solid var(--border)}
.logout-btn{width:100%;padding:8px;background:none;border:1px solid var(--border);border-radius:8px;color:var(--text2);font-size:12px;cursor:pointer;font-family:inherit;transition:all .2s}
.logout-btn:hover{border-color:var(--danger);color:var(--danger)}
.main{flex:1;margin-left:220px;padding:24px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.topbar h1{font-size:20px;font-weight:700}
.hamburger{display:none;background:none;border:none;color:var(--text);cursor:pointer;padding:8px}

/* Page visibility */
.page{display:none}.page.active{display:block;animation:fadeIn .25s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

/* Cards */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px}
.card-title{font-size:14px;font-weight:600;color:var(--text2);margin-bottom:14px;display:flex;align-items:center;gap:8px}
.card-title svg{width:16px;height:16px;color:var(--accent)}

/* Stats grid */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:14px;margin-bottom:24px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px}
.stat-card .label{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
.stat-card .value{font-size:20px;font-weight:700;color:#fff}
.stat-card .value.green{color:var(--accent)}
.stat-card .value.red{color:var(--danger)}

/* Buttons */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:8px;border:none;font-size:13px;font-weight:600;cursor:pointer;transition:all .15s;font-family:inherit}
.btn-primary{background:var(--accent);color:#0b1120}.btn-primary:hover{background:var(--accent2)}
.btn-danger{background:rgba(239,68,68,.15);color:var(--danger);border:1px solid rgba(239,68,68,.25)}.btn-danger:hover{background:rgba(239,68,68,.25)}
.btn-ghost{background:var(--surface2);color:var(--text2);border:1px solid var(--border)}.btn-ghost:hover{color:var(--text);border-color:var(--accent)}
.btn-sm{padding:5px 10px;font-size:12px;border-radius:6px}
.btn-xs{padding:3px 8px;font-size:11px;border-radius:5px}

/* Table */
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 12px;color:var(--text2);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border)}
td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
tr:hover td{background:rgba(255,255,255,.02)}
.mono{font-family:'Courier New',monospace;font-size:11.5px;color:var(--accent);word-break:break-all}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}
.badge-on{background:rgba(0,212,170,.1);color:var(--accent)}
.badge-off{background:rgba(239,68,68,.1);color:var(--danger)}
.badge-expired{background:rgba(245,158,11,.1);color:var(--warn)}
.dot{width:6px;height:6px;border-radius:50%;display:inline-block}
.dot-on{background:var(--accent);box-shadow:0 0 6px var(--accent)}
.dot-off{background:var(--danger)}

/* Toggle switch */
.toggle{position:relative;width:40px;height:22px;cursor:pointer;display:inline-block}
.toggle input{display:none}
.toggle .slider{position:absolute;inset:0;background:#334155;border-radius:11px;transition:.2s}
.toggle .slider::before{content:'';position:absolute;width:18px;height:18px;left:2px;top:2px;background:#fff;border-radius:50%;transition:.2s}
.toggle input:checked+.slider{background:var(--accent)}
.toggle input:checked+.slider::before{transform:translateX(18px)}

/* Modal */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);z-index:100;display:none;align-items:center;justify-content:center;padding:16px}
.modal-overlay.show{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:24px;width:100%;max-width:440px;animation:fadeIn .2s ease}
.modal h3{font-size:16px;margin-bottom:16px}
.form-group{margin-bottom:14px}
.form-group label{display:block;font-size:12px;color:var(--text2);margin-bottom:5px;font-weight:600}
.form-group input,.form-group select{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;color:var(--text);font-size:13px;outline:none;transition:border .2s;font-family:inherit}
.form-group input:focus,.form-group select:focus{border-color:var(--accent)}
.form-row{display:flex;gap:12px}
.form-row .form-group{flex:1}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}

/* Toast */
.toast{position:fixed;bottom:24px;right:24px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 20px;font-size:13px;z-index:200;transform:translateY(100px);opacity:0;transition:all .3s;pointer-events:none}
.toast.show{transform:translateY(0);opacity:1}
.toast.ok{border-color:var(--accent);color:var(--accent)}
.toast.err{border-color:var(--danger);color:var(--danger)}

/* Settings section */
.settings-section{margin-bottom:24px}
.settings-section h3{font-size:14px;font-weight:600;margin-bottom:12px;color:var(--text2)}
.addr-list{display:flex;flex-direction:column;gap:6px;margin:10px 0}
.addr-item{display:flex;align-items:center;justify-content:space-between;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-size:13px}

/* Responsive */
@media(max-width:768px){
  .sidebar{transform:translateX(-100%)}
  .sidebar.open{transform:translateX(0)}
  .main{margin-left:0}
  .hamburger{display:block}
  .stats-grid{grid-template-columns:repeat(2,1fr)}
  .form-row{flex-direction:column;gap:0}
}
@media(max-width:480px){
  .stats-grid{grid-template-columns:1fr}
  .main{padding:16px}
  .topbar h1{font-size:17px}
  .modal{padding:18px}
}

/* Service control */
.svc-controls{display:flex;gap:8px;align-items:center}
.svc-dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.svc-dot.on{background:var(--accent);box-shadow:0 0 8px var(--accent);animation:pulse 2s infinite}
.svc-dot.off{background:var(--danger)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
</style></head>
<body>

<div class="layout">
  <!-- Sidebar -->
  <aside class="sidebar" id="sidebar">
    <div class="brand"><span>USF</span><small id="panelVer"></small></div>
    <nav>
      <button class="nav-item active" onclick="go('overview')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
        Overview
      </button>
      <button class="nav-item" onclick="go('inbounds')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
        Inbounds
      </button>
      <button class="nav-item" onclick="go('settings')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
        Settings
      </button>
      <button class="nav-item" onclick="go('backup')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Backup
      </button>
      <button class="nav-item" onclick="go('logs')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        Logs
      </button>
    </nav>
    <div class="footer">
      <button class="logout-btn" onclick="logout()">Logout</button>
    </div>
  </aside>

  <!-- Main -->
  <div class="main">
    <div class="topbar">
      <div style="display:flex;align-items:center;gap:12px">
        <button class="hamburger" onclick="document.getElementById('sidebar').classList.toggle('open')">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
        </button>
        <h1 id="pageTitle">Overview</h1>
      </div>
      <div class="svc-controls">
        <span class="svc-dot" id="svcDot"></span>
        <span style="font-size:12px;color:var(--text2)" id="svcText"></span>
        <button class="btn btn-xs btn-ghost" onclick="toggleService()" id="svcBtn"></button>
      </div>
    </div>

    <!-- Overview Page -->
    <div class="page active" id="page-overview">
      <div class="stats-grid" id="statsGrid"></div>
      <div class="card"><div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>Active Connections</div>
      <div id="connList" style="font-size:13px;color:var(--text2)">Loading...</div></div>
    </div>

    <!-- Inbounds Page -->
    <div class="page" id="page-inbounds">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px">
        <span style="font-size:13px;color:var(--text2)" id="linksCount"></span>
        <button class="btn btn-primary" onclick="openAddModal()">+ Add Inbound</button>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="table-wrap">
          <table><thead><tr>
            <th>Name</th><th>UUID</th><th>Status</th><th>Traffic</th><th>Conns</th><th>Actions</th>
          </tr></thead><tbody id="linksBody"></tbody></table>
        </div>
      </div>
    </div>

    <!-- Settings Page -->
    <div class="page" id="page-settings">
      <div class="card settings-section">
        <h3>Custom Domain</h3>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
          <input id="domainInput" placeholder="e.g. myproxy.com (leave empty for default)" style="flex:1;min-width:200px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;color:var(--text);font-size:13px;outline:none;font-family:inherit">
          <button class="btn btn-primary" onclick="saveDomain()">Save</button>
        </div>
      </div>
      <div class="card settings-section">
        <h3>Custom Addresses (for subscription)</h3>
        <div id="addrList" class="addr-list"></div>
        <div style="display:flex;gap:8px;margin-top:10px">
          <input id="addrInput" placeholder="e.g. cloudfront.net" style="flex:1;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;color:var(--text);font-size:13px;outline:none;font-family:inherit">
          <button class="btn btn-primary" onclick="addAddress()">Add</button>
        </div>
      </div>
      <div class="card settings-section">
        <h3>Change Password</h3>
        <div class="form-group"><label>Current Password</label><input type="password" id="curPw"></div>
        <div class="form-group"><label>New Password</label><input type="password" id="newPw"></div>
        <button class="btn btn-primary" onclick="changePw()">Change Password</button>
      </div>
    </div>

    <!-- Backup Page -->
    <div class="page" id="page-backup">
      <div class="card settings-section">
        <h3>Download Backup</h3>
        <p style="font-size:13px;color:var(--text2);margin-bottom:12px">Download a full backup of all inbounds, settings and data.</p>
        <button class="btn btn-primary" onclick="window.location.href='/api/backup'">Download JSON Backup</button>
      </div>
      <div class="card settings-section">
        <h3>Restore Backup</h3>
        <p style="font-size:13px;color:var(--text2);margin-bottom:12px">Upload a previously downloaded backup file. This will replace all current data.</p>
        <input type="file" id="restoreFile" accept=".json" style="margin-bottom:10px;font-size:13px;color:var(--text2)">
        <button class="btn btn-danger" onclick="restoreBackup()">Restore from File</button>
      </div>
    </div>

    <!-- Logs Page -->
    <div class="page" id="page-logs">
      <div class="card">
        <div class="card-title">Recent Errors</div>
        <div id="errorLogs" style="font-size:12px;font-family:monospace;max-height:400px;overflow-y:auto;color:var(--text2)">Loading...</div>
      </div>
    </div>

  </div>
</div>

<!-- Add/Edit Modal -->
<div class="modal-overlay" id="linkModal">
  <div class="modal">
    <h3 id="modalTitle">Add Inbound</h3>
    <input type="hidden" id="editUid">
    <div class="form-group"><label>Name</label><input id="mLabel" placeholder="e.g. My Client"></div>
    <div class="form-row">
      <div class="form-group"><label>Traffic Limit</label><input id="mLimitVal" type="number" min="0" value="0" placeholder="0 = unlimited"></div>
      <div class="form-group"><label>Unit</label><select id="mLimitUnit"><option value="GB">GB</option><option value="MB">MB</option><option value="TB">TB</option></select></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>Max Connections (0=unlimited)</label><input id="mMaxConn" type="number" min="0" value="0"></div>
      <div class="form-group"><label>Expiry (days, 0=never)</label><input id="mExpiry" type="number" min="0" value="0"></div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary" id="modalSaveBtn" onclick="saveLink()">Create</button>
    </div>
  </div>
</div>

<!-- Config Modal -->
<div class="modal-overlay" id="configModal">
  <div class="modal" style="max-width:520px">
    <h3 id="cfgTitle">Config</h3>
    <div class="form-group"><label>VLESS Link</label>
      <div style="display:flex;gap:6px"><input id="cfgLink" readonly style="flex:1;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;color:var(--accent);font-size:12px;font-family:monospace;outline:none"><button class="btn btn-xs btn-ghost" onclick="copyText('cfgLink')">Copy</button></div>
    </div>
    <div class="form-group"><label>Subscription URL</label>
      <div style="display:flex;gap:6px"><input id="cfgSub" readonly style="flex:1;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;color:var(--accent);font-size:12px;font-family:monospace;outline:none"><button class="btn btn-xs btn-ghost" onclick="copyText('cfgSub')">Copy</button></div>
    </div>
    <div class="modal-actions"><button class="btn btn-ghost" onclick="document.getElementById('configModal').classList.remove('show')">Close</button></div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const api = (url, opts) => fetch(url, {credentials:'include', ...opts}).then(r => {if(!r.ok) return r.json().then(d => {throw new Error(d.detail||'Error')}); return r.json()});
const $ = id => document.getElementById(id);
let currentPage = 'overview';
let linksCache = [];
let statsInterval, linksInterval;

function toast(msg, ok=true) {
  const t = $('toast'); t.textContent = msg; t.className = 'toast show ' + (ok?'ok':'err');
  setTimeout(() => t.className = 'toast', 2500);
}

function copyText(id) {
  const el = $(id); navigator.clipboard.writeText(el.value).then(() => toast('Copied!')).catch(() => {el.select(); document.execCommand('copy'); toast('Copied!')});
}

function go(page) {
  currentPage = page;
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const pg = $('page-'+page); if(pg) pg.classList.add('active');
  event && event.target && event.target.closest('.nav-item') && event.target.closest('.nav-item').classList.add('active');
  const titles = {overview:'Overview',inbounds:'Inbounds',settings:'Settings',backup:'Backup',logs:'Logs'};
  $('pageTitle').textContent = titles[page] || page;
  $('sidebar').classList.remove('open');
  if(page === 'inbounds') loadLinks();
  if(page === 'settings') loadSettings();
  if(page === 'logs') loadLogs();
  if(page === 'overview') loadStats();
}

// ── Stats ──────────────────────────────────────────────────────
function loadStats() {
  api('/api/stats').then(d => {
    $('panelVer').textContent = d.panelVer || '';
    $('svcDot').className = 'svc-dot ' + (d.running ? 'on' : 'off');
    $('svcText').textContent = d.running ? 'Running' : 'Stopped';
    $('svcBtn').textContent = d.running ? 'Stop' : 'Start';
    $('statsGrid').innerHTML = [
      s('CPU', d.cpu+'%', ''), s('RAM', d.ramUsed+' / '+d.ramTotal, ''), 
      s('Upload', d.upload, 'green'), s('Download', d.download, 'green'),
      s('Connections', d.activeConns, d.activeConns>0?'green':''),
      s('Total Traffic', d.totalTraffic+' MB', ''),
      s('Requests', d.totalRequests, ''), s('Errors', d.totalErrors, d.totalErrors>0?'red':''),
      s('Uptime', d.uptime, ''), s('Service', d.serviceUptime, ''),
      s('Links', d.linksCount, ''), s('Swap', d.swap, ''), s('Disk', d.disk, ''),
    ].map(h => '<div class="stat-card"><div class="label">'+h[0]+'</div><div class="value '+h[2]+'">'+h[1]+'</div></div>').join('');
    // Connections
    api('/api/logs').then(l => {
      if(l.connections.length === 0) { $('connList').innerHTML = '<span style="color:var(--text2)">No active connections</span>'; return; }
      $('connList').innerHTML = '<table style="width:100%"><tr><th>UUID</th><th>IP</th><th>Bytes</th><th>Since</th></tr>' + l.connections.map(c => '<tr><td class="mono" style="font-size:11px">'+c.uuid.substring(0,16)+'...</td><td>'+c.ip+'</td><td>'+formatB(c.bytes)+'</td><td style="font-size:11px;color:var(--text2)">'+c.at+'</td></tr>').join('') + '</table>';
    }).catch(() => {});
  }).catch(() => {});
}

function s(l,v,c) { return [l,v,c]; }
function formatB(b) { if(b>=1073741824) return (b/1073741824).toFixed(2)+' GB'; if(b>=1048576) return (b/1048576).toFixed(2)+' MB'; if(b>=1024) return (b/1024).toFixed(1)+' KB'; return b+' B'; }

// ── Service ────────────────────────────────────────────────────
async function toggleService() {
  const d = await api('/api/stats').catch(()=>({running:false}));
  const url = d.running ? '/api/service/stop' : '/api/service/restart';
  api(url, {method:'POST'}).then(() => { toast(d.running?'Service stopped':'Service restarted'); setTimeout(loadStats, 500); }).catch(e => toast(e.message, false));
}

// ── Links / Inbounds ───────────────────────────────────────────
function loadLinks() {
  api('/api/links').then(d => {
    linksCache = d.links || [];
    $('linksCount').textContent = linksCache.length + ' inbound(s)';
    if(linksCache.length === 0) { $('linksBody').innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text2);padding:30px">No inbounds yet</td></tr>'; return; }
    $('linksBody').innerHTML = linksCache.map(l => {
      const statusCls = !l.active ? 'off' : l.expired ? 'expired' : 'on';
      const statusTxt = !l.active ? 'Disabled' : l.expired ? 'Expired' : 'Active';
      const used = formatB(l.used_bytes);
      const limit = l.limit_bytes > 0 ? formatB(l.limit_bytes) : 'Unlimited';
      return '<tr>'+
        '<td style="font-weight:600">'+esc(l.label)+'</td>'+
        '<td class="mono" style="font-size:10px;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+l.uuid+'</td>'+
        '<td><span class="badge badge-'+statusCls+'"><span class="dot dot-'+statusCls+'"></span>'+statusTxt+'</span></td>'+
        '<td style="font-size:12px">'+used+' / '+limit+'</td>'+
        '<td>'+l.current_connections+'</td>'+
        '<td style="white-space:nowrap">'+
          '<button class="btn btn-xs btn-ghost" onclick="showConfig(\''+l.uuid+'\')">Config</button> '+
          '<label class="toggle" title="Toggle active"><input type="checkbox" '+(l.active?'checked':'')+' onchange="toggleLink(\''+l.uuid+'\',this.checked)"><span class="slider"></span></label> '+
          '<button class="btn btn-xs btn-ghost" onclick="editLink(\''+l.uuid+'\')">Edit</button> '+
          '<button class="btn btn-xs btn-danger" onclick="deleteLink(\''+l.uuid+'\')">Del</button>'+
        '</td></tr>';
    }).join('');
  }).catch(e => toast(e.message, false));
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function openAddModal() {
  $('modalTitle').textContent = 'Add Inbound';
  $('modalSaveBtn').textContent = 'Create';
  $('editUid').value = '';
  $('mLabel').value = '';
  $('mLimitVal').value = '0';
  $('mLimitUnit').value = 'GB';
  $('mMaxConn').value = '0';
  $('mExpiry').value = '0';
  $('linkModal').classList.add('show');
}

function editLink(uid) {
  const l = linksCache.find(x => x.uuid === uid);
  if(!l) return;
  $('modalTitle').textContent = 'Edit Inbound';
  $('modalSaveBtn').textContent = 'Save';
  $('editUid').value = uid;
  $('mLabel').value = l.label;
  if(l.limit_bytes > 0) {
    if(l.limit_bytes >= 1099511627776) { $('mLimitVal').value = (l.limit_bytes/1099511627776); $('mLimitUnit').value = 'TB'; }
    else if(l.limit_bytes >= 1073741824) { $('mLimitVal').value = (l.limit_bytes/1073741824); $('mLimitUnit').value = 'GB'; }
    else { $('mLimitVal').value = (l.limit_bytes/1048576); $('mLimitUnit').value = 'MB'; }
  } else { $('mLimitVal').value = '0'; $('mLimitUnit').value = 'GB'; }
  $('mMaxConn').value = l.max_connections;
  $('mExpiry').value = '';
  $('linkModal').classList.add('show');
}

function closeModal() { $('linkModal').classList.remove('show'); }

async function saveLink() {
  const uid = $('editUid').value;
  const body = {
    label: $('mLabel').value.trim(),
    limit_value: parseFloat($('mLimitVal').value) || 0,
    limit_unit: $('mLimitUnit').value,
    max_connections: parseInt($('mMaxConn').value) || 0,
    expiry_days: parseFloat($('mExpiry').value) || 0,
  };
  if(!body.label) { toast('Name is required', false); return; }
  try {
    if(uid) {
      await api('/api/links/'+uid, {method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
      toast('Updated!');
    } else {
      await api('/api/links', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
      toast('Created!');
    }
    closeModal();
    loadLinks();
  } catch(e) { toast(e.message, false); }
}

async function toggleLink(uid, active) {
  try { await api('/api/links/'+uid, {method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({active})}); loadLinks(); }
  catch(e) { toast(e.message, false); loadLinks(); }
}

async function deleteLink(uid) {
  if(!confirm('Delete this inbound?')) return;
  try { await api('/api/links/'+uid, {method:'DELETE'}); toast('Deleted!'); loadLinks(); }
  catch(e) { toast(e.message, false); }
}

function showConfig(uid) {
  const l = linksCache.find(x => x.uuid === uid);
  if(!l) return;
  $('cfgTitle').textContent = l.label;
  $('cfgLink').value = l.vless_link;
  $('cfgSub').value = l.sub_url;
  $('configModal').classList.add('show');
}

// ── Settings ───────────────────────────────────────────────────
function loadSettings() {
  api('/api/domain').then(d => $('domainInput').value = d.domain || '').catch(()=>{});
  api('/api/addresses').then(d => {
    const list = d.addresses || [];
    $('addrList').innerHTML = list.length === 0 ? '<span style="color:var(--text2);font-size:13px">No custom addresses</span>' :
      list.map((a,i) => '<div class="addr-item"><span>'+esc(a)+'</span><button class="btn btn-xs btn-danger" onclick="delAddr('+i+')">Remove</button></div>').join('');
  }).catch(()=>{});
}

async function saveDomain() {
  try { await api('/api/domain', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({domain:$('domainInput').value})}); toast('Domain saved!'); }
  catch(e) { toast(e.message, false); }
}

async function addAddress() {
  const a = $('addrInput').value.trim();
  if(!a) return;
  try { await api('/api/addresses', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({address:a})}); $('addrInput').value=''; toast('Address added!'); loadSettings(); }
  catch(e) { toast(e.message, false); }
}

async function delAddr(i) {
  try { await api('/api/addresses/'+i, {method:'DELETE'}); toast('Removed!'); loadSettings(); }
  catch(e) { toast(e.message, false); }
}

async function changePw() {
  const cur = $('curPw').value, nw = $('newPw').value;
  if(!cur || !nw) { toast('Fill both fields', false); return; }
  try { await api('/api/change-password', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({current_password:cur, new_password:nw})}); toast('Password changed!'); $('curPw').value=''; $('newPw').value=''; }
  catch(e) { toast(e.message, false); }
}

// ── Backup ─────────────────────────────────────────────────────
async function restoreBackup() {
  const file = $('restoreFile').files[0];
  if(!file) { toast('Select a file', false); return; }
  if(!confirm('This will replace all data. Continue?')) return;
  try {
    const text = await file.text();
    await api('/api/restore', {method:'POST', headers:{'Content-Type':'application/json'}, body:text});
    toast('Restored! Reloading...'); setTimeout(() => location.reload(), 1000);
  } catch(e) { toast(e.message, false); }
}

// ── Logs ───────────────────────────────────────────────────────
function loadLogs() {
  api('/api/logs').then(d => {
    const errs = d.errors || [];
    $('errorLogs').innerHTML = errs.length === 0 ? '<span style="color:var(--text2)">No errors</span>' :
      errs.map(e => '<div style="padding:6px 0;border-bottom:1px solid var(--border)"><span style="color:var(--danger)">[ERROR]</span> <span style="color:var(--text2)">'+e.time+'</span><br>'+esc(e.error)+'</div>').join('');
  }).catch(()=>{ $('errorLogs').textContent = 'Failed to load'; });
}

// ── Auth ───────────────────────────────────────────────────────
async function logout() {
  await fetch('/api/logout', {method:'POST', credentials:'include'});
  window.location.href = '/login';
}

// ── Init ───────────────────────────────────────────────────────
api('/api/me').then(d => { if(!d.auth) window.location.href = '/login'; }).catch(() => window.location.href = '/login');
loadStats();
statsInterval = setInterval(loadStats, 5000);

// Close modals on overlay click
$('linkModal').onclick = e => { if(e.target === $('linkModal')) closeModal(); };
$('configModal').onclick = e => { if(e.target === $('configModal')) $('configModal').classList.remove('show'); };
</script>
</body></html>"""

# ── Page Routes ───────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_page(req: Request):
    if await valid_session(req.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/dashboard")
    return HTMLResponse(LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(req: Request):
    if not await valid_session(req.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/login")
    return HTMLResponse(DASHBOARD_HTML)

@app.get("/inbounds", response_class=HTMLResponse)
async def inbounds_redirect(req: Request):
    return RedirectResponse("/dashboard")

# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)