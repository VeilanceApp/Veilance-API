#!/bin/bash
set -e

ip="${1:-127.0.0.1}"
port="${2:-80}"
ncore=$(nproc 2>/dev/null || echo 1)
workers=$(( (ncore / 2) + 1 ))
gunicorn \
  --daemon \
  --bind "${ip}:${port}" \
  --workers "${workers}" \
  --timeout 400 \
  --access-logfile "veilance-access.log" \
  --error-logfile "veilance-error.log" \
  --pid "veilance-gunicorn.pid" \
  wsgi:app
