#!/bin/bash

set -euo pipefail
set -x

DATABASE_URL=postgres://$PGUSER:$PGPASSWORD@$PGHOST:$PGPORT/$PGDATABASE /usr/local/src/bin/migrate-all /usr/local/src/schema
echo ===== dump schema =====
pg_dump --schema-only -U glvd glvd
echo ===== dump schema =====

/usr/local/src/ingest-postgres.sh

pg_dump --schema-only -U glvd glvd > /tmp/glvd-schema.sql
pg_dump -U glvd glvd > /tmp/glvd-dump.sql
