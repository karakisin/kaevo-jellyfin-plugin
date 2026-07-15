FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY kaevo_relay ./kaevo_relay
RUN pip install --no-cache-dir .
EXPOSE 8200
# Access logging is disabled because playback grants are carried in the path.
CMD ["uvicorn", "kaevo_relay.app:app", "--host", "0.0.0.0", "--port", "8200", "--no-access-log"]
