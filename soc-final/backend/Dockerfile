FROM python:3.11-slim

# Use a non-root user for better security
RUN adduser --disabled-password --gecos "" appuser

WORKDIR /app

# Install build dependencies for packages like faiss (if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libatlas-base-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . ./

# Ensure the env file is copied (for local development via docker-compose)
# (docker-compose will also pass env vars via env_file)

# Run uvicorn
EXPOSE 8000
USER appuser
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
