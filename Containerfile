FROM docker.io/library/debian:trixie-slim

RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends python3-asyncpg python3-pip python3-poetry-core python3-requests python3-sqlalchemy && \
    apt-get upgrade -y --no-install-recommends git curl debian-archive-keyring postgresql-client jq gettext-base
COPY . /usr/local/src
COPY keyring.asc /etc/apt/trusted.gpg.d/keyring.asc
RUN pip install --break-system-packages --no-deps --editable /usr/local/src
