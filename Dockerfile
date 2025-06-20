FROM python:3.11-slim

WORKDIR /app

# Install system dependencies and security updates
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Use the PORT environment variable or default to 5000
EXPOSE ${PORT:-5000}

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Use environment variable for port binding
CMD gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 120 --log-level info --access-logfile - --error-logfile - main:app
