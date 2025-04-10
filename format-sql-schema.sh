#!/bin/bash
set -e
set -x

podman build -t localhost/pg-formatter:latest -f Containerfile.pg-formatter .

find schema -iname "*.sql" -print0 | while IFS= read -r -d '' file; do
    echo Formatting "$file"..
    podman run --rm --volume "$(pwd):/work" localhost/pg-formatter:latest -i /work/"$file"
done
