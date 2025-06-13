
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml ./
COPY uv.lock* ./

RUN pip install --no-cache-dir uv
RUN uv pip install --system --no-cache flask flask-login flask-sqlalchemy requests psycopg2-binary werkzeug flask-limiter flask-session python-dotenv gunicorn

COPY . .

EXPOSE 5000

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

RUN adduser --disabled-password --gecos '' appuser && chown -R appuser:appuser /app
USER appuser

CMD ["sh", "-c", "set -a && if [ -f ./.env ]; then echo 'Loading .env file...' && . ./.env && echo 'Environment loaded from .env'; else echo 'No .env file found, using system environment variables'; fi && set +a && echo 'Starting gunicorn...' && gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 --log-level info --access-logfile - --error-logfile - main:app"]
