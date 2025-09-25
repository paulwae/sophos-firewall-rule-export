FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8

WORKDIR /app
COPY sophos-firewall-rule-export.py /app/export.py

ENTRYPOINT ["python", "/app/export.py"]
