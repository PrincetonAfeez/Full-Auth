FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN adduser --disabled-password --gecos "" appuser
# Install the LOCKED, tested dependency set for reproducible, verified deploys.
COPY requirements.lock /app/
RUN pip install --no-cache-dir -r requirements.lock

COPY . /app/
RUN DJANGO_SECRET_KEY=build-time python manage.py collectstatic --noinput

USER appuser

# Graceful shutdown: gunicorn drains on SIGTERM; the worker handles it in its own command.
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--graceful-timeout", "30"]
