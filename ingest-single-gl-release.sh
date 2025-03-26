#!/bin/bash

set -euo pipefail
set -x

# Workaround to import a new Garden Linux release that is not yet part of the GLRD, but already has the apt repo available

# Assert that GL_VERSIONS_WITH_SOURCE_REPO is non-empty and contains a single version number in the form of 123.3
if [[ -z "$GL_VERSIONS_WITH_SOURCE_REPO" ]]; then
    echo "Error: GL_VERSIONS_WITH_SOURCE_REPO is empty"
    exit 1
fi

if ! [[ "$GL_VERSIONS_WITH_SOURCE_REPO" =~ ^[0-9]+\.[0-9]+$ ]]; then
    echo "Error: GL_VERSIONS_WITH_SOURCE_REPO does not contain a single version number in the form of 123.3"
    exit 1
fi

echo Ingesting packages for Garden Linux "$GL_VERSIONS_WITH_SOURCE_REPO"

envsubst < /usr/local/src/conf/ingest-debsrc/gardenlinux.sources.template > /usr/local/src/conf/ingest-debsrc/gardenlinux.sources

echo "Run data ingestion (ingest-debsrc - gardenlinux $GL_VERSIONS_WITH_SOURCE_REPO)"
python3 -m glvd.cli.data.ingest_debsrc gardenlinux "$GL_VERSIONS_WITH_SOURCE_REPO" "/usr/local/src/data/ingest-debsrc/gardenlinux/lists/packages.gardenlinux.io_gardenlinux_dists_${GL_VERSIONS_WITH_SOURCE_REPO}_main_source_Sources"
