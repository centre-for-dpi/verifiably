FROM python:3.11-slim
# Versions pinned and wheels only. Unpinned, a rebuild silently picks up
# whatever the index serves that day; and without --only-binary a source
# distribution gets to run arbitrary setup.py code at BUILD time, as root,
# inside CI. Bump these deliberately.
RUN pip install --no-cache-dir --only-binary :all: \
      fastapi==0.115.6 \
      "uvicorn[standard]==0.34.0" \
      httpx==0.28.1 \
      python-multipart==0.0.20 \
      "psycopg[binary]==3.2.3"
WORKDIR /app
COPY app.py .

# python:slim runs as root by default. Nothing here needs it: the app only
# reads app.py and talks to Postgres over the network.
RUN useradd --system --uid 10001 --no-create-home appuser
USER 10001:10001

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
