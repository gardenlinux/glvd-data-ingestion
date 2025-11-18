FROM docker.io/library/debian:stable-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        python3-asyncpg \
        python3-pip \
        python3-poetry-core \
        python3-requests \
        python3-sqlalchemy \
        python3-psycopg2 \
        git \
        debian-archive-keyring \
        jq \
        gettext-base

RUN install -d /usr/share/postgresql-common/pgdg && \
    curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail https://www.postgresql.org/media/keys/ACCC4CF8.asc && \
    . /etc/os-release && \
    sh -c "echo 'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $VERSION_CODENAME-pgdg main' > /etc/apt/sources.list.d/pgdg.list"

RUN apt-get update && \
    apt-get install -y --no-install-recommends postgresql-client-18

ADD version.txt /version.txt

COPY . /usr/local/src
COPY keyring.asc /etc/apt/trusted.gpg.d/keyring.asc
RUN pip install --break-system-packages --no-deps --editable /usr/local/src
