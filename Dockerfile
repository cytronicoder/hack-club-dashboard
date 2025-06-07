
FROM python:3.11-slim

WORKDIR /app

# Copy dependency files
COPY pyproject.toml ./

# Install dependencies directly with pip
RUN pip install --no-cache-dir flask flask-login flask-sqlalchemy requests psycopg2-binary werkzeug flask-limiter gunicorn

# Copy application code
COPY . .

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 4 --timeout 120 main:app"]
