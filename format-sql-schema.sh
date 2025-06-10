#!/bin/bash
set -e
set -x

if [ ! -f pgformatter.tgz ]; then
    curl -H "Authorization: Bearer $GITHUB_TOKEN" -L -o pgformatter.tgz https://github.com/darold/pgFormatter/archive/refs/tags/v5.6.tar.gz
fi

podman build -t localhost/pg-formatter:latest -f Containerfile.pg-formatter .

find schema -iname "*.sql" -print0 | while IFS= read -r -d '' file; do
    echo Formatting "$file"..
    podman run --rm --volume "$(pwd):/work" localhost/pg-formatter:latest -i /work/"$file"
done
