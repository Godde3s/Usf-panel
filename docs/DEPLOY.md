# 📦 Deployment Guide

This guide covers all deployment options for Usf Panel.

## Option 1: HuggingFace Spaces (Free, Recommended)

### Step-by-step

1. **Create a HuggingFace account** at [huggingface.co/join](https://huggingface.co/join) (if you don't have one)

2. **Create a new Space:**
   - Go to [huggingface.co/new-space](https://huggingface.co/new-space)
   - **Name:** `usf` (or anything you like)
   - **SDK:** `Docker`
   - **Visibility:** `Public` (free) or `Private` (free for personal use)
   - Click **Create Space**

3. **Upload files:**
   - Go to the **Files** tab of your Space
   - Click **Add file → Upload file**
   - Upload these three files:
     - `app.py`
     - `requirements.txt`
     - `Dockerfile`

4. **Add Secrets:**
   - Go to **Settings** tab
   - Scroll to **Repository secrets**
   - Click **New secret**:
     - Name: `ADMIN_USERNAME`, Value: `admin`
     - Name: `ADMIN_PASSWORD`, Value: `your-strong-password`
     - Name: `SECRET_KEY`, Value: `any-random-string-of-64-chars`

5. **Wait for the build:**
   - Go back to the **App** tab
   - The build takes ~2 minutes
   - You'll see "Building" → "Running"

6. **Visit your panel:**
   - URL: `https://{your-username}-{space-name}.hf.space`
   - You'll be redirected to `/login`
   - Login with your admin credentials

### HuggingFace Limitations

| Limit | Value |
|-------|-------|
| RAM | 16 GB |
| CPU | 2 vCPU |
| Disk | 50 GB (ephemeral) |
| Restart | Every 48 hours (or on idle) |
| Bandwidth | ~10 Mbps (free tier) |
| Port | 7860 only (HTTPS) |

> ⚠️ The disk is **ephemeral** — files outside `/tmp` may not persist. Usf Panel stores its SQLite database at `/tmp/usf.db` to survive restarts within the 48-hour window, but **data is lost when the Space is rebuilt**. For permanent storage, use HuggingFace's persistent storage (paid) or back up regularly via the `/api/backup` endpoint.

---

## Option 2: Local / VPS

### Prerequisites
- Python 3.11 or newer
- Linux or macOS (Windows works but uvloop is not available)

### Steps

```bash
# 1. Clone the repo
git clone https://github.com/godde3s/Usf-panel.git
cd Usf-panel

# 2. (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set environment variables
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=your-strong-password
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# 5. Run
python app.py

# → Panel available at http://localhost:7860
```

### Running behind Nginx (recommended for VPS)

If you want to use port 443 directly (not just 7860), put Nginx in front:

```nginx
# /etc/nginx/sites-available/usf
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:7860;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:7860;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }
}
```

---

## Option 3: Docker

### Using the included Dockerfile

```bash
# Build
docker build -t usf-panel .

# Run
docker run -d \
  --name usf \
  -p 7860:7860 \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=your-strong-password \
  -e SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))") \
  -v usf-data:/tmp \
  usf-panel

# → Panel available at http://localhost:7860
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'
services:
  usf:
    build: .
    ports:
      - "7860:7860"
    environment:
      - ADMIN_USERNAME=admin
      - ADMIN_PASSWORD=your-strong-password
      - SECRET_KEY=change-me-to-a-random-64-char-string
    volumes:
      - usf-data:/tmp
    restart: unless-stopped

volumes:
  usf-data:
```

```bash
docker-compose up -d
```

---

## Environment Variables Reference

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `PORT` | `7860` | No | Port to listen on (HF requires 7860) |
| `ADMIN_USERNAME` | `admin` | No | Admin login username |
| `ADMIN_PASSWORD` | `admin` | **Yes** | Admin login password — **change this!** |
| `SECRET_KEY` | `Usf-default-secret-key` | **Yes** | Used for password hashing and session tokens |
| `WS_HMAC_KEY` | (random) | No | HMAC key for signing WS paths (auto-generated if unset) |
| `SPACE_HOST` | `localhost` | No | Detected automatically on HuggingFace |
| `DB_PATH` | `/tmp/usf.db` | No | SQLite database path |
| `PANEL_VERSION` | `v1.0.0` | No | Panel version (shown in UI) |
| `CORE_VERSION` | `v26.4.25` | No | Core version (shown in UI) |
| `TELEGRAM_HANDLE` | `@Usf` | No | Telegram handle (shown in UI) |

---

## Post-Deployment Checklist

After deploying, verify:

- [ ] Visit `https://your-domain/login` — login page should appear
- [ ] Login with default credentials — should redirect to `/dashboard`
- [ ] **Change the password** via Settings → Change Password
- [ ] Create a test inbound via Inbounds → Add Inbound
- [ ] Visit the status page at `/status/{uuid}` — should show the premium UI
- [ ] Copy the VLESS link and import it into your client
- [ ] Verify the tunnel works (visit a website)
- [ ] Run an IP leak test at [ipleak.net](https://ipleak.net)
- [ ] Back up your config via Settings → Backup (download JSON)

---

## Backup & Restore

### Backup
```bash
curl -b "Usf_session=YOUR_SESSION_COOKIE" \
  https://your-domain/api/backup \
  -o backup.json
```

### Restore
```bash
curl -X POST -b "Usf_session=YOUR_SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -d @backup.json \
  https://your-domain/api/restore
```

---

## Troubleshooting

### "502 Bad Gateway" on HuggingFace
- The Space is still building. Wait 2 minutes and refresh.
- If it persists, check the **Logs** tab in your Space settings.

### Login fails with "Invalid username or password"
- Verify `ADMIN_USERNAME` and `ADMIN_PASSWORD` secrets are set correctly.
- Default is `admin` / `admin` if no secrets are set.

### WebSocket connection fails
- Make sure your client is using `wss://` (not `ws://`).
- Make sure the path is `/ws/{uuid}/{hmac_token}` (not just `/ws/{uuid}`).
- Check that the link is active in the dashboard.

### Speed is slow
- See [Speed Optimization Guide](SPEED_OPTIMIZATION.md).
- Try a different clean IP.
- Check if your client is using mux.

### Data is lost after restart
- This is expected on HuggingFace free tier (ephemeral disk).
- Use `/api/backup` regularly to save your config.
- Or upgrade to HuggingFace persistent storage (paid).
