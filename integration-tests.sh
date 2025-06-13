#!/bin/bash
set -e

# Check if PostgreSQL is running on localhost:5432
if ! nc -z localhost 5432; then
    echo "PostgreSQL is not running on localhost:5432"
    echo "Run:"
    echo "  make && make run"
    echo "in tests/integration/db and re-run the test."
    exit 1
fi

PYTHONPATH=src pytest -vv tests/integration/
