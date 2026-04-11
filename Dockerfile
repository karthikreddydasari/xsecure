# Dockerfile for xsecure — Incident Response RL Environment
# Compatible with HF Spaces (port 7860) and local Docker

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY models.py      .
COPY client.py      .
COPY graders.py     .
COPY tasks.py       .
COPY inference.py   .
COPY baseline.py    .
COPY __init__.py    .
COPY openenv.yaml   .
COPY server/        server/

ENV TASK_ID=1
ENV HOST=0.0.0.0
ENV PORT=7860
ENV WORKERS=4
ENV MAX_CONCURRENT_ENVS=100

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

CMD uvicorn server.app:app \
        --host $HOST \
        --port $PORT \
        --workers $WORKERS
