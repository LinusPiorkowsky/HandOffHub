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

# Make start script executable
RUN chmod +x start.sh

# Railway will set PORT automatically
EXPOSE 8080

# Use the shell script to start the app
CMD ["./start.sh"]
