FROM python:3.11-slim

LABEL maintainer="Usf"
LABEL description="VLESS tunnel & subscription panel"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 7860

CMD ["python", "-c", "import uvicorn; uvicorn.run('app:app', host='0.0.0.0', port=7860, log_level='info', access_log=False)"]