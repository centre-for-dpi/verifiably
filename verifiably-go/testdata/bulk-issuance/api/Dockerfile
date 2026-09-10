# Minimal container for the citizen-service mock API.
#
# Alpine + system psycopg2 avoids compiling a wheel on startup and keeps the
# image under 60 MB. One file, no build tooling at runtime.
FROM python:3.12-alpine

RUN apk add --no-cache libpq \
  && pip install --no-cache-dir psycopg2-binary==2.9.9

WORKDIR /app
COPY citizen_service.py /app/citizen_service.py

# Defaults match the docker-compose wiring: citizens-postgres is reachable by
# its compose service name on the waltid_default network. Override at
# `docker run` time (-e CITIZENS_DSN=...) for any other layout.
ENV CITIZENS_DSN=postgres://citizens:citizens@citizens-postgres:5432/citizens \
    PORT=8099 \
    HOST=0.0.0.0

EXPOSE 8099

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O- http://127.0.0.1:${PORT}/health || exit 1

# Demo fixture, but it still should not run as root — the compose stack mounts
# it alongside real services and it is the kind of thing that gets copied.
RUN useradd --system --uid 10002 --no-create-home appuser
USER 10002:10002

CMD ["python", "/app/citizen_service.py"]
