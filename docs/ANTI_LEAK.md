# 🛡️ Anti-IP-Leak & Anti-Ban Guide

This document explains every anti-leak and anti-ban measure built into Usf Panel, and what you (the user) should do on your side to maximize protection.

## Server-Side Protections (automatic)

### 1. HMAC-Signed WebSocket Paths

**What:** Instead of `/ws/{uuid}` (which can be enumerated by attackers), the tunnel now requires `/ws/{uuid}/{hmac_token}` where `hmac_token` is a 16-character HMAC-SHA256 of the UUID signed with a server-side secret.

**Why it matters:**
- ❌ Without this, an attacker can scan `/ws/{uuid1}`, `/ws/{uuid2}`, etc. and discover all valid tunnels.
- ✅ With this, each link's WS path is unique and unpredictable.

**Backwards compatible:** Old clients without the token still work (legacy mode), but new VLESS URLs always include it.

### 2. HTTP Header Sanitization Middleware

**What:** Every HTTP response goes through a middleware that:
- Strips: `Server`, `X-Powered-By`, `Via`, `X-Forwarded-Host`, `X-AspNet-Version`
- Forces: `Server: Usf` (generic, no version)
- Adds security headers:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - `Referrer-Policy: no-referrer`
  - `X-XSS-Protection: 1; mode=block`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains` (HTTPS only)

**Why it matters:** Scanners (like Shodan, Censys) fingerprint servers by their headers. With these stripped, the panel blends in with thousands of other HTTPS services.

### 3. Login Rate Limiting

**What:** Maximum 5 login attempts per IP per 60 seconds. The 6th attempt gets HTTP 429.

**Why it matters:** Prevents brute-force attacks on the admin password.

### 4. Secure Cookies

**What:** The session cookie is set with:
- `Secure=True` — only sent over HTTPS
- `HttpOnly=True` — not accessible from JavaScript (anti-XSS)
- `SameSite=Lax` — anti-CSRF

### 5. No IP in Subscription Comments

**What:** The subscription file (`/sub/{uid}`) only contains:
- Friendly metadata (label, usage, expiry)
- VLESS links (which use the domain, not the IP)

**Why it matters:** If the subscription file is intercepted, the real server IP is not exposed.

## Client-Side VLESS Config Protections (automatic)

### 1. uTLS Chrome Fingerprint (`fp=chrome`)

**What:** During the TLS handshake, the client mimics Google Chrome's TLS ClientHello (cipher suites, extensions, ordering).

**Why it matters:** A naive VLESS client has a distinctive TLS fingerprint that DPI (Deep Packet Inspection) can detect and block. With `fp=chrome`, the connection is indistinguishable from a real Chrome browsing session.

### 2. Mux with xUDP Packet Encoding

**What:** Multiplexes 8 concurrent streams over a single TCP connection, with xUDP packet encoding that makes UDP traffic look like TCP.

**Why it matters:** Looks like a single browser connection to DPI, rather than 8 separate connections.

### 3. ALPN `http/1.1`

**What:** The TLS ALPN extension advertises `http/1.1` (not `h2`).

**Why it matters:** Matches what a real WebSocket-over-TLS connection looks like in a browser.

## Recommended User-Side Protections

Even with all server-side protections, **you** must take these steps on your client:

### ❌ 1. Disable IPv6 in your client

**Why:** Your ISP may assign you an IPv6 address that leaks even when the proxy is on.

**How (V2RayN):**
- Settings → Core: DNS → Check "Disable IPv6"

**How (V2RayNG):**
- Settings → VPN settings → Check "Block IPv6"

### 🌐 2. Route DNS through the proxy

**Why:** If your DNS queries go through your local ISP, they can see which domains you're visiting (DNS leak).

**How (V2RayN):**
- Settings → Core: DNS → Remote DNS = `https://1.1.1.1/dns-query`

**How (V2RayNG):**
- Settings → DNS → Remote DNS = `1.1.1.1`

### 🚫 3. Disable WebRTC in your browser

**Why:** WebRTC can leak your real IP address even when behind a proxy.

**How (Chrome/Edge):**
- Install "Disable WebRTC" extension
- Or use [Brave Browser](https://brave.com) (WebRTC is restricted by default)

**How (Firefox):**
- Go to `about:config`
- Set `media.peerconnection.enabled` = `false`

### 🔁 4. Always use mux

**Why:** Multiplexing reduces the number of connections, making traffic analysis harder.

**How:** Already enabled in the VLESS URL (`mux=1&muxConcurrency=8`). Just make sure your client doesn't override it.

### 🌐 5. Use a reputable client

**Recommended clients (in order of anti-leak quality):**

| Client | Platform | Anti-leak features |
|--------|----------|-------------------|
| **V2RayN** 6.x+ | Windows | Full uTLS, mux, DNS routing |
| **V2RayNG** 1.8+ | Android | Full uTLS, mux, DNS routing |
| **Streisand** 1.6+ | iOS | Full uTLS, mux |
| **Shadowrocket** 2.2.40+ | iOS | Full uTLS, mux |
| **Foxray** | macOS | Full uTLS, mux |
| **Nekoray** | Windows/Linux | Full uTLS, mux, DNS routing |

### 🚫 6. Don't share your subscription URL

**Why:** Anyone with your `/sub/{uid}` URL can use your quota.

**Best practices:**
- Don't post your VLESS link in public channels
- Don't share the `/status/{uuid}` URL publicly (it shows your quota info)
- Use the **Share Card** button (coming soon) to share a redacted screenshot instead

## Testing for Leaks

### 1. IP leak test
- Visit [ipleak.net](https://ipleak.net) through the proxy
- Verify: only the proxy server's IP should be visible
- Verify: no IPv6 address should be visible
- Verify: DNS servers should be the proxy's DNS (not your ISP's)

### 2. WebRTC leak test
- Visit [browserleaks.com/webrtc](https://browserleaks.com/webrtc) through the proxy
- Verify: no local IP addresses should be visible

### 3. DNS leak test
- Visit [dnsleaktest.com](https://dnsleaktest.com) through the proxy
- Run the "Extended test"
- Verify: only the proxy's DNS servers should be visible

### 4. Fingerprint test
- Visit [tlsfingerprint.io](https://tlsfingerprint.io) through the proxy
- Verify: the TLS fingerprint matches Chrome's

## Anti-Ban Best Practices

If you're using the proxy for platforms that aggressively ban proxy users (Instagram, TikTok, Twitter, etc.):

### 1. Use a clean IP
- Add a clean IP via the dashboard (Clean IP page)
- Avoid datacenter IPs that are known to be VPN endpoints
- Best: use a residential IP service (separate from this panel)

### 2. Don't switch IPs frequently
- Each IP switch looks suspicious to anti-fraud systems
- Pick one clean IP and stick with it

### 3. Disable proxy when not needed
- Use split-tunneling: route only specific apps through the proxy
- V2RayN: Routing → "Bypass mainland China" + "Bypass LAN"

### 4. Use a real browser, not a bot framework
- Anti-bot systems can detect Selenium/Puppeteer fingerprints
- Use a real Chrome/Firefox with manual browsing

### 5. Don't use the same IP for multiple accounts
- If you're managing multiple accounts, create separate Usf links and use a different clean IP for each

## Reporting Issues

If you discover an IP leak or a bypass, please open an issue on GitHub: https://github.com/godde3s/Usf-panel/issues
