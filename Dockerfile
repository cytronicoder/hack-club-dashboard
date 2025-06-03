
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml ./
COPY uv.lock* ./

RUN pip install --no-cache-dir uv
RUN uv pip install --system --no-cache flask flask-login flask-sqlalchemy requests psycopg2-binary werkzeug flask-limiter

COPY . .

EXPOSE 5000

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

RUN adduser --disabled-password --gecos '' appuser && chown -R appuser:appuser /app
USER appuser

CMD ["python3", "main.py"]
