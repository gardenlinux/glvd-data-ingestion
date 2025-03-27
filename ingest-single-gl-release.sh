#!/bin/bash

set -euo pipefail
set -x

# Workaround to import a new Garden Linux release that is not yet part of the GLRD, but already has the apt repo available

# Check if $1 is provided and matches the pattern 123.3
if [[ $# -lt 1 ]]; then
    echo "Error: Missing argument. Please provide a version number in the form of 123.3."
    exit 1
fi

if ! [[ "$1" =~ ^[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Argument does not match the required version pattern (e.g., 123.3)."
    exit 1
fi

pushd $(mktemp -d)

GARDENLINUX_VERSION="$1"

wcurl https://packages.gardenlinux.io/gardenlinux/dists/"$GARDENLINUX_VERSION"/main/source/Sources.gz
gunzip Sources.gz


echo "Run data ingestion (ingest-debsrc - gardenlinux $GARDENLINUX_VERSION)"
python3 -m glvd.cli.data.ingest_debsrc gardenlinux "$GARDENLINUX_VERSION" "$PWD"/Sources

echo "Run data combination (combine-deb)"
python3 -m glvd.cli.data.combine_deb
echo "Run data combination (combine-all)"
python3 -m glvd.cli.data.combine_all

popd
