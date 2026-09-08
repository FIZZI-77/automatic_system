FROM postgres:16-bookworm

ARG PATRONI_VERSION=4.1.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gettext-base \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        pgbackrest \
        postgresql-16-postgis-3 \
        postgresql-16-postgis-3-scripts \
        python3-venv \
    && python3 -m venv /opt/patroni \
    && /opt/patroni/bin/pip install --no-cache-dir \
        "patroni[kubernetes]==${PATRONI_VERSION}" \
        "psycopg2-binary==2.9.10" \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/patroni/bin:${PATH}"

COPY k8s/build/postgres-ha/entrypoint.sh /usr/local/bin/patroni-entrypoint
RUN chmod 0755 /usr/local/bin/patroni-entrypoint

ENTRYPOINT ["/usr/local/bin/patroni-entrypoint"]
