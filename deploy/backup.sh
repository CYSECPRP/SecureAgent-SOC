#!/usr/bin/env bash
# Dumps the production PostgreSQL database to backups/ and keeps the newest 14 dumps.
# Daily at 02:30 with cron: 30 2 * * * cd /path/to/SecureAgent-SOC && ./deploy/backup.sh
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p backups

file="backups/secureagent-$(date +%Y%m%d-%H%M%S).sql.gz"
# shellcheck disable=SC2016  # the variables expand inside the postgres container
docker compose -f docker-compose.prod.yml exec -T postgres \
  sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' | gzip > "$file.partial"
mv "$file.partial" "$file"

find backups -maxdepth 1 -name 'secureagent-*.sql.gz' -type f | sort -r | tail -n +15 | xargs -r rm --
echo "Saved $file"
