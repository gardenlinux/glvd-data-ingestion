# Garden Linux Vulnerability Database - Data Ingestion

This repository contains the code for gathering data needed by the Garden Linux Security Tracker [glvd](https://github.com/gardenlinux/glvd) to process vulnerability requests from users.

Currently, data for the following distributions is collected:
* Debian Buster
* Debian Bulleye
* Debian Bookworm
* Debian Trixie
* Garden Linux today

## Dev setup

Download the apt sources index file with the help of this container image:

```bash
podman build -t sources-index-downloader -f Containerfile.apt-source
podman run localhost/sources-index-downloader:latest > package-list
```

With this file, you can run the debsrc parser like so:

```bash
python -m venv venv
source venv/bin/activate
poetry install
python3 -m glvd.data.debsrc package-list
```

### Run ingestion locally

Configure the postgres db credentials (`PG..` env vars)


```
export PGUSER=glvd
export PGDATABASE=glvd
export PGPASSWORD=glvd
export PGHOST=localhost
export PGPORT=5432
```

```
python3 -m glvd.cli.data.ingest_debsrc gardenlinux today path/to/package-list
```

(Replace `today` with the version, like `1443`)

