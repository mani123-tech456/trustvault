FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRUSTVAULT_HOST=0.0.0.0 \
    TRUSTVAULT_DATA=/var/lib/trustvault \
    PORT=10000

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --create-home --uid 10001 trustvault \
    && mkdir -p /var/lib/trustvault \
    && chown -R trustvault:trustvault /var/lib/trustvault
COPY --chown=trustvault:trustvault app.py schema.sql web ./
USER trustvault
EXPOSE 10000
VOLUME ["/var/lib/trustvault"]
CMD ["python", "app.py"]
