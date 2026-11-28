# syntax=docker/dockerfile:1
# Blink 2.0: payment page integrity monitoring (PCI DSS 6.4.3 / 11.6.1).
#
#   docker build -t blink .
#   docker run --rm --read-only --tmpfs /tmp -v blink-data:/data blink scan --fail-on high
#
# Runs as the non-root "pwuser" from the Playwright image. The root filesystem can be mounted
# read-only: everything Blink writes goes to /data (blink.yaml, .blink/ store, reports) or /tmp.
ARG PLAYWRIGHT_VERSION=1.65.2
FROM mcr.microsoft.com/playwright/python:v${PLAYWRIGHT_VERSION}-noble

ARG PLAYWRIGHT_VERSION
LABEL org.opencontainers.image.title="Blink" \
      org.opencontainers.image.description="Payment page script and header integrity monitoring (PCI DSS 6.4.3 / 11.6.1)" \
      org.opencontainers.image.source="https://github.com/danielguillaumont/blink" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/blink \
    PATH=/opt/blink/bin:$PATH \
    HOME=/tmp \
    BLINK_CONFIG=/data/blink.yaml

COPY pyproject.toml README.md LICENSE /tmp/build/
COPY src /tmp/build/src
# The base image has pip but no ensurepip: create the venv without pip and install into it
# with the system pip, so Blink's dependencies stay isolated from the system packages.
RUN python3 -m venv --without-pip /opt/blink \
 && pip --python /opt/blink/bin/python install "/tmp/build[capture,server]" "playwright==${PLAYWRIGHT_VERSION}" \
 && rm -rf /tmp/build \
 && mkdir -p /data \
 && chown pwuser:pwuser /data

COPY --chmod=0755 docker/healthcheck.py /usr/local/bin/blink-healthcheck
COPY --chmod=0755 docker/demo-setup.sh /usr/local/bin/blink-demo-setup

USER pwuser
WORKDIR /data
VOLUME ["/data"]

# Each service sets BLINK_HEALTHCHECK_URL to an endpoint on its own loopback (lab: /checkout,
# serve: /healthz, daemon: /metrics). Without it the check only confirms Blink starts.
HEALTHCHECK --interval=15s --timeout=6s --start-period=20s --retries=4 \
  CMD ["/opt/blink/bin/python", "/usr/local/bin/blink-healthcheck"]

ENTRYPOINT ["blink"]
CMD ["--help"]
