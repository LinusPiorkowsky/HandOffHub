# Dockerfile
FROM python:3.11-slim

# Arbeitsverzeichnis
WORKDIR /app

# System-Dependencies für PostgreSQL
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Python Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App-Dateien kopieren
COPY . .

# Port - Railway setzt PORT automatisch
EXPOSE 8080

# Start-Befehl: Nur Gunicorn starten (DB init passiert in app.py)
CMD gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120
