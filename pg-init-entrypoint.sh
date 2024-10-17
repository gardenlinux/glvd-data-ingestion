#!/bin/bash

echo "$PGHOST:$PGPORT:$PGDATABASE:$PGUSER:$PGPASSWORD" > ~/.pgpass
chmod 0600 ~/.pgpass

dropdb --force --if-exists glvd
createdb glvd
psql glvd -f /glvd.sql
