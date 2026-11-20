#!/usr/bin/env bash
# Runs every time the codespace starts: waits for Docker, then starts PostgreSQL, Redis, Qdrant and OPA.
set -euo pipefail

for _ in $(seq 1 30); do
  docker info >/dev/null 2>&1 && break
  sleep 2
done
docker compose up -d
