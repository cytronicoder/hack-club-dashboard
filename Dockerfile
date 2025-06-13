
FROM python:3.11-slim

WORKDIR /app

# Copy requirements first for better caching
COPY pyproject.toml ./
RUN pip install --no-cache-dir flask flask-login flask-sqlalchemy requests psycopg2-binary werkzeug flask-limiter flask-session python-dotenv gunicorn

# Copy application code
COPY . .

# Use the PORT environment variable or default to 5000
EXPOSE ${PORT:-5000}

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Use environment variable for port binding
CMD gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 120 --log-level info --access-logfile - --error-logfile - main:app
