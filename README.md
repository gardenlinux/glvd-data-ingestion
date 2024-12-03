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

#### Database setup

```bash
podman network create glvd
podman run -it --rm --name=glvd-postgres --network=glvd --publish 5432:5432 --env POSTGRES_USER=glvd --env POSTGRES_DB=glvd --env POSTGRES_PASSWORD=glvd ghcr.io/gardenlinux/glvd-postgres:latest
podman run -it --rm --network=glvd --env PGHOST=glvd-postgres ghcr.io/gardenlinux/glvd-init:latest
```


Configure the postgres db credentials (`PG..` env vars)


```bash
export PGUSER=glvd
export PGDATABASE=glvd
export PGPASSWORD=glvd
export PGHOST=localhost
export PGPORT=5432
```

#### Run ingestion

```bash
python -m venv venv
source venv/bin/activate
poetry install
python3 -m glvd.cli.data.ingest_debsrc gardenlinux today path/to/package-list
python3 -m glvd.cli.data.ingest_nvd
```

(Replace `today` with the version, like `1443`)
