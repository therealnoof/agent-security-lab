# =============================================================
#  Comms agent — Dockerfile
# =============================================================
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py agent-card.json .

EXPOSE 9100

CMD ["python", "agent.py"]
