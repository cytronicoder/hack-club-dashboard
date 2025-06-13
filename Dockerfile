
FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir flask flask-login flask-sqlalchemy requests psycopg2-binary werkzeug flask-limiter flask-session python-dotenv gunicorn

EXPOSE 5000

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60", "main:app"]
