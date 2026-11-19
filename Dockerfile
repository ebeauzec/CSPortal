# CSPortal: one image, one process, one data directory. Copyright (c) 2026 Obi1 - FZCO. See LICENSE.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    CSPORTAL_CONFIG=/etc/csportal/config.json CSPORTAL_DATA_DIR=/data

# Take operating-system security fixes that are newer than the base image (the image scan in CI gates on this).
RUN apt-get update && apt-get -y --no-install-recommends upgrade && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin csportal \
 && mkdir -p /data /etc/csportal && chown csportal /data

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY csportal ./csportal

USER csportal
VOLUME ["/data"]
EXPOSE 8443 8444
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8443/healthz', timeout=4)" || exit 1
ENTRYPOINT ["python", "-m", "csportal"]
CMD ["serve"]
