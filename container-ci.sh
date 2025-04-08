#!/bin/bash

set -euo pipefail
set -x

psql glvd -f /usr/local/src/schema/glvd-db-schema.sql
/usr/local/src/ingest-postgres.sh
pg_dump --schema-only -U glvd glvd
pg_dump -U glvd glvd > /tmp/glvd-dump.sql
