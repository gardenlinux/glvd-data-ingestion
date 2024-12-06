#!/bin/bash

set -euo pipefail
set -x

START=$(date +%s)

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
python3 -m glvd.cli.data.ingest_debsrc debian trixie /usr/local/src/data/ingest-debsrc/debian/lists/deb.debian.org_debian_dists_trixie_main_source_Sources
echo "Run data ingestion (ingest-debsrc - debian bookworm)"
python3 -m glvd.cli.data.ingest_debsrc debian bookworm /usr/local/src/data/ingest-debsrc/debian/lists/deb.debian.org_debian_dists_bookworm_main_source_Sources
echo "Run data ingestion (ingest-debsec - debian)"
python3 -m glvd.cli.data.ingest_debsec debian security-tracker/data

echo "Run data ingestion (ingest-debsrc - gardenlinux today)"
python3 -m glvd.cli.data.ingest_debsrc gardenlinux today /usr/local/src/data/ingest-debsrc/gardenlinux/lists/packages.gardenlinux.io_gardenlinux_dists_today_main_source_Sources

echo "Run data ingestion (ingest-debsrc - gardenlinux 1592)"
python3 -m glvd.cli.data.ingest_debsrc gardenlinux 1592 /usr/local/src/data/ingest-debsrc/gardenlinux/lists/packages.gardenlinux.io_gardenlinux_dists_1592.4_main_source_Sources


echo "Run data ingestion (nvd)"
echo date before nvd
date -u +%Y-%m-%dT%H:%M:%S%Z
START_NVD=$(date +%s);
python3 -m glvd.cli.data.ingest_nvd
echo date after nvd
date -u +%Y-%m-%dT%H:%M:%S%Z
END_NVD=$(date +%s);
echo $((END_NVD-START_NVD)) | awk '{printf "Duration of nvd import: %d:%02d:%02d\n", $1/3600, ($1/60)%60, $1%60}'


echo "Run data combination (combine-deb)"
python3 -m glvd.cli.data.combine_deb
echo "Run data combination (combine-all)"
python3 -m glvd.cli.data.combine_all


# taken from https://stackoverflow.com/a/20249534
END=$(date +%s);
echo $((END-START)) | awk '{printf "Duration of run: %d:%02d:%02d\n", $1/3600, ($1/60)%60, $1%60}'
