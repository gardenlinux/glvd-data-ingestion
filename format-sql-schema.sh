#!/bin/bash
set -e

podman build -t pg-formatter -f Containerfile.pg-formatter .


files=$(find schema -iname "*.sql");
for file in $files;
do
  podman run --rm --volume "$(pwd):/work" localhost/foo:latest -i /work/"$file"
done;
