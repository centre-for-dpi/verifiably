# Minimal container for the citizen-service mock API.
#
# Alpine + system psycopg2 avoids compiling a wheel on startup and keeps the
# image under 60 MB. One file, no build tooling at runtime.
FROM python:3.12-alpine

RUN apk add --no-cache libpq \
  && pip install --no-cache-dir psycopg2-binary==2.9.9

WORKDIR /app
COPY citizen_service.py /app/citizen_service.py

# Default matches verifiably-go's main stack: citizens-postgres is reachable
# by its compose service name on the waltid_default network. Its real
# password is CITIZENS_PG_PASSWORD from verifiably-go's own .env (generated
# on `deploy.sh setup`) — "citizens" here only matches a host that predates
# that variable. This repo's own docker-compose.yml (the standalone ministry
# scenario) overrides this entirely with its own citizens-db container, so
# this default only matters for a bare `docker run` against the main stack.
# Override at `docker run` time (-e CITIZENS_DSN=...) for any other layout.
ENV CITIZENS_DSN=postgres://citizens:citizens@citizens-postgres:5432/citizens \
    PORT=8099 \
    HOST=0.0.0.0

EXPOSE 8099

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O- http://127.0.0.1:${PORT}/health || exit 1

CMD ["python", "/app/citizen_service.py"]
