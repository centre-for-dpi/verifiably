FROM python:3.11-slim
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" httpx python-multipart "psycopg[binary]"
WORKDIR /app
COPY app.py .
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
