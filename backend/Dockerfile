FROM python:3.11-slim

WORKDIR /app

# System dependencies for scientific python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/backend/requirements.txt
COPY backend/requirements.lock /app/backend/requirements.lock
RUN pip install --no-cache-dir -r /app/backend/requirements.lock

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin raptor

# Copy application code
COPY backend/ /app/backend/
COPY data/ /app/data/
RUN chown -R raptor:raptor /app

WORKDIR /app/backend

EXPOSE 8000

USER raptor

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
