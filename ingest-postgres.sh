#!/bin/bash

set -euo pipefail

mkdir -p data/ingest-debsec/{debian,gardenlinux}/CVE
mkdir -p data/ingest-debsec/debian/CVE
mkdir -p data/ingest-debsrc/debian
mkdir -p data/ingest-debsrc/var/lib/dpkg
touch data/ingest-debsrc/var/lib/dpkg/status
curl https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/CVE/list?ref_type=heads \
    --output data/ingest-debsec/debian/CVE/list
mkdir -p conf/ingest-debsrc/
curl https://raw.githubusercontent.com/gardenlinux/glvd-data-ingestion/main/conf/ingest-debsrc/apt.conf \
    --output conf/ingest-debsrc/apt.conf
curl https://raw.githubusercontent.com/gardenlinux/glvd-data-ingestion/main/conf/ingest-debsrc/debian.sources \
    --output conf/ingest-debsrc/debian.sources
curl https://github.com/gardenlinux/gardenlinux/raw/refs/heads/main/keyring.gpg \
    --output /usr/share/keyrings/gardenlinux-archive-keyring.gpg
APT_CONFIG=conf/ingest-debsrc/apt.conf apt-get -q update \
-o Dir="$PWD/data/ingest-debsrc/" \
-o Dir::Etc::sourcelist="$PWD/conf/ingest-debsrc/debian.sources" \
-o Dir::State="$PWD/data/ingest-debsrc/"
APT_CONFIG=conf/ingest-debsrc/apt.conf apt-get -q update \
-o Dir="$PWD/data/ingest-debsrc/" \
-o Dir::Etc::sourcelist="$PWD/conf/ingest-debsrc/gardenlinux.sources" \
-o Dir::State="$PWD/data/ingest-debsrc/"

git clone --depth=1 https://salsa.debian.org/security-tracker-team/security-tracker

echo "Run data ingestion (ingest-debsrc - debian trixie)"
glvd-data ingest-debsrc debian trixie data/ingest-debsrc/lists/deb.debian.org_debian_dists_trixie_main_source_Sources
echo "Run data ingestion (ingest-debsrc - debian bookworm)"
glvd-data ingest-debsrc debian bookworm data/ingest-debsrc/lists/deb.debian.org_debian_dists_bookworm_main_source_Sources
echo "Run data ingestion (ingest-debsec - debian)"
glvd-data ingest-debsec debian security-tracker/data

echo "Run data ingestion (ingest-debsrc - gardenlinux today)"
glvd-data ingest-debsrc gardenlinux today ./gardenlinux-packages/today

echo "Run data ingestion (nvd)"
glvd-data ingest-nvd
echo "Run data combination (combine-deb)"
glvd-data combine-deb
echo "Run data combination (combine-all)"
glvd-data combine-all
