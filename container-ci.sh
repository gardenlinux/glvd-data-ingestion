#!/bin/bash

set -euo pipefail
set -x

DATABASE_URL=glvd /usr/local/src/bin/migrate-all /usr/local/src/schema
/usr/local/src/ingest-postgres.sh
pg_dump --schema-only -U glvd glvd
pg_dump -U glvd glvd > /tmp/glvd-dump.sql
