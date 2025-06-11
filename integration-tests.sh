#!/bin/bash

podman build -t localhost/glvd-postgres-integration-test:latest tests/integration/db
podman run --detach --name=glvd-postgres-integration-test --publish 5432:5432 --env POSTGRES_USER=glvd --env POSTGRES_DB=glvd --env POSTGRES_PASSWORD=glvd localhost/glvd-postgres-integration-test:latest postgres -c log_statement=all

sleep 20

PYTHONPATH=src pytest -vv tests/integration/
