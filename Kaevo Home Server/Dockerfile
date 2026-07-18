FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV KAEVO_HOME_SERVER_DATA_DIR=/data

WORKDIR /app

RUN addgroup --system kaevo && adduser --system --ingroup kaevo kaevo

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY kaevo_home_server /app/kaevo_home_server

USER kaevo

EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8100/api/v1/status', timeout=3).read()" || exit 1

CMD ["uvicorn", "kaevo_home_server.main:app", "--host", "0.0.0.0", "--port", "8100"]
