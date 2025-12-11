#!/bin/bash

set -euo pipefail
set -x

START=$(date +%s)

GL_VERSIONS_WITH_SOURCE_REPO=$(curl https://gardenlinux-glrd.s3.eu-central-1.amazonaws.com/releases-minor.json |  jq --join-output '.releases[] | select(.attributes.source_repo==true) | "\(.version.major).\(.version.minor) "')
export GL_VERSIONS_WITH_SOURCE_REPO

echo Supporting Garden Linux versions "$GL_VERSIONS_WITH_SOURCE_REPO"


# fixme
pip install --break-system-packages python-debian


envsubst < /usr/local/src/conf/ingest-debsrc/gardenlinux.sources.template > /usr/local/src/conf/ingest-debsrc/gardenlinux.sources

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
git clone --depth=1 https://git.kernel.org/pub/scm/linux/security/vulns.git

find /usr/local/src/data -name '*source_Sources'

echo "Run data ingestion (ingest-debsrc - debian forky)"
python3 -m glvd.cli.data.ingest_debsrc debian forky /usr/local/src/data/ingest-debsrc/debian/lists/deb.debian.org_debian_dists_forky_main_source_Sources
echo "Run data ingestion (ingest-debsrc - debian trixie)"
python3 -m glvd.cli.data.ingest_debsrc debian trixie /usr/local/src/data/ingest-debsrc/debian/lists/deb.debian.org_debian_dists_trixie_main_source_Sources
echo "Run data ingestion (ingest-debsrc - debian bookworm)"
python3 -m glvd.cli.data.ingest_debsrc debian bookworm /usr/local/src/data/ingest-debsrc/debian/lists/deb.debian.org_debian_dists_bookworm_main_source_Sources
echo "Run data ingestion (ingest-debsec - debian)"
python3 -m glvd.cli.data.ingest_debsec debian security-tracker/data

echo "Run data ingestion (ingest-debsrc - gardenlinux today)"
python3 -m glvd.cli.data.ingest_debsrc gardenlinux today /usr/local/src/data/ingest-debsrc/gardenlinux/lists/packages.gardenlinux.io_gardenlinux_dists_today_main_source_Sources




for version in $GL_VERSIONS_WITH_SOURCE_REPO; do
    echo "Run data ingestion (ingest-debsrc - gardenlinux $version)"
    python3 -m glvd.cli.data.ingest_debsrc gardenlinux "$version" "/usr/local/src/data/ingest-debsrc/gardenlinux/lists/packages.gardenlinux.io_gardenlinux_dists_${version}_main_source_Sources"
done



UNRELEASED_PATCH_VERSIONS=$(python3 /usr/local/src/unreleased-patch-versions.py "$GL_VERSIONS_WITH_SOURCE_REPO")

for unreleased in $UNRELEASED_PATCH_VERSIONS; do
    # Import with empty file for unreleased versions, this allows us to add cve context for those versions
    # Only if package list is actually empty
    RESPONSE=$(curl -s https://security.gardenlinux.org/v1/distro/"$unreleased")
    if [[ $RESPONSE = "[]" ]]; then
        EMPTY_FILE=$(mktemp)
        echo "Run data ingestion (ingest-debsrc - gardenlinux $unreleased)"
        python3 -m glvd.cli.data.ingest_debsrc gardenlinux "$unreleased" "$EMPTY_FILE"
    fi
done

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

echo "Ingest changelogs to identify fixed CVEs"
for version in $GL_VERSIONS_WITH_SOURCE_REPO; do
    date -u +%Y-%m-%dT%H:%M:%S%Z
    START_CHANGELOG=$(date +%s);
    echo "Run changelog ingestion (ingest_changelogs - gardenlinux $version)"
    python3 -m glvd.cli.data.ingest_changelogs "$version"
    date -u +%Y-%m-%dT%H:%M:%S%Z
    END_CHANGELOG=$(date +%s);
    echo "-- CHANGELOG IMPORT PERFORMANCE MEASUREMENT for $version --"
    echo $((END_CHANGELOG-START_CHANGELOG)) | awk '{printf "Duration of changelog import: %d:%02d:%02d\n", $1/3600, ($1/60)%60, $1%60}'
done

echo "Run kernel CVE ingestion"
python3 -m glvd.cli.data.ingest_kernel vulns/cve/published/

# taken from https://stackoverflow.com/a/20249534
END=$(date +%s);
echo $((END-START)) | awk '{printf "Duration of run: %d:%02d:%02d\n", $1/3600, ($1/60)%60, $1%60}'

DATABASE_URL=postgres://$PGUSER:$PGPASSWORD@$PGHOST:$PGPORT/$PGDATABASE python3 /usr/local/src/src/glvd/import-source-manifest.py --manifest-dir=/usr/local/src/data/sourcemanifests/
