FROM python:3.11-slim
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" httpx python-multipart "psycopg[binary]"
WORKDIR /app
COPY app.py .

# python:slim runs as root by default. Nothing here needs it: the app only
# reads app.py and talks to Postgres over the network.
RUN useradd --system --uid 10001 --no-create-home appuser
USER 10001:10001

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
