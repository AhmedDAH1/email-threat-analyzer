FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

RUN useradd -m -u 1000 appuser && chown -R appuser /app
USER appuser

EXPOSE 8000

# Production WSGI server (gunicorn) instead of Flask's dev server.
# HOST/PORT respected via env; default binds all interfaces for containers.
ENV HOST=0.0.0.0 PORT=8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "web_app:app"]
