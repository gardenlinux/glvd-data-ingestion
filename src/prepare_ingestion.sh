#!/bin/bash

set -e

# Install Debian Keyring
apt-get update
apt-get install -y debian-archive-keyring

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
