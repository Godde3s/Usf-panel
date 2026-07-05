FROM python:3.11-slim

# ─── Anti-fingerprint: don't leak OS version in image labels ─────────────────
LABEL maintainer="Usf"
LABEL description="VLESS tunnel & subscription panel"

WORKDIR /app

# ─── Install deps first (better Docker layer caching) ────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ─── Copy app source ─────────────────────────────────────────────────────────
COPY app.py .

# ─── Health check (HF uses this to know when the Space is ready) ─────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://localhost:7860/health', timeout=5); sys.exit(0)" || exit 1

# ─── HF Spaces expects the app on port 7860 ─────────────────────────────────
EXPOSE 7860

# ─── Run with maximum performance flags ─────────────────────────────────────
# uvloop for event loop, httptools for HTTP parsing, websockets for WS
CMD ["python", "app.py"]
