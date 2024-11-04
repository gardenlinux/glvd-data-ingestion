#!/bin/bash

set -euo pipefail
set -x

mkdir -p /usr/local/src/data/ingest-debsec/{debian,gardenlinux}/CVE
mkdir -p /usr/local/src/data/ingest-debsec/debian/CVE
mkdir -p /usr/local/src/data/ingest-debsrc/{debian,gardenlinux}
mkdir -p /usr/local/src/data/ingest-debsrc/var/lib/dpkg
touch /usr/local/src/data/ingest-debsrc/var/lib/dpkg/status
curl https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/CVE/list?ref_type=heads \
    --output /usr/local/src/data/ingest-debsec/debian/CVE/list
mkdir -p /usr/local/src/conf/ingest-debsrc/

export APT_CONFIG=/usr/local/src/conf/ingest-debsrc/apt.conf 

apt-get update \
-o Dir="/usr/local/src/data/ingest-debsrc/debian/" \
-o Dir::Etc::sourcelist="/usr/local/src/conf/ingest-debsrc/debian.sources" \
-o Dir::State="/usr/local/src/data/ingest-debsrc/debian/"

apt-get update \
-o Dir="/usr/local/src/data/ingest-debsrc/gardenlinux/" \
-o Dir::Etc::sourcelist="/usr/local/src/conf/ingest-debsrc/gardenlinux.sources" \
-o Dir::State="/usr/local/src/data/ingest-debsrc/gardenlinux/"

git clone --depth=1 https://salsa.debian.org/security-tracker-team/security-tracker

find /usr/local/src/data -name '*source_Sources'

echo "Run data ingestion (ingest-debsrc - debian trixie)"
glvd-data ingest-debsrc debian trixie /usr/local/src/data/ingest-debsrc/debian/lists/deb.debian.org_debian_dists_trixie_main_source_Sources
echo "Run data ingestion (ingest-debsrc - debian bookworm)"
glvd-data ingest-debsrc debian bookworm /usr/local/src/data/ingest-debsrc/debian/lists/deb.debian.org_debian_dists_bookworm_main_source_Sources
echo "Run data ingestion (ingest-debsec - debian)"
glvd-data ingest-debsec debian security-tracker/data

echo "Run data ingestion (ingest-debsrc - gardenlinux today)"
glvd-data ingest-debsrc gardenlinux today /usr/local/src/data/ingest-debsrc/gardenlinux/lists/packages.gardenlinux.io_gardenlinux_dists_today_main_source_Sources

echo "Run data ingestion (nvd)"
glvd-data ingest-nvd
echo "Run data combination (combine-deb)"
glvd-data combine-deb
echo "Run data combination (combine-all)"
glvd-data combine-all
