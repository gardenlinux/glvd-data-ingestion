#!/bin/bash

set -e

# Install Debian Keyring
sudo apt update
sudo apt install -y debian-archive-keyring

# Prepare: mount directories
mkdir -p tmp/ingest-debsec/{debian,gardenlinux}/CVE
mkdir -p tmp/ingest-debsrc/debian
mkdir -p tmp/ingest-debsrc/var/lib/dpkg
touch tmp/ingest-debsrc/var/lib/dpkg/status

# Prepare: ingest-debsec
curl https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/CVE/list?ref_type=heads \
    --output tmp/ingest-debsec/debian/CVE/list
cp -p data/CVE/list tmp/ingest-debsec/gardenlinux/CVE/list

# Prepare: ingest-debsrc
APT_CONFIG=conf/ingest-debsrc/apt.conf apt update \
  -o Dir="$PWD/tmp/ingest-debsrc/" \
  -o Dir::Etc::sourcelist="$PWD/conf/ingest-debsrc/debian.sources" \
  -o Dir::State="$PWD/tmp/ingest-debsrc/"
