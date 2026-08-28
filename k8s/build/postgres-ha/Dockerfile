FROM postgis/postgis:16-3.4

ARG PATRONI_VERSION=4.1.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl gettext-base pgbackrest python3-venv \
    && python3 -m venv /opt/patroni \
    && /opt/patroni/bin/pip install --no-cache-dir \
        "patroni[kubernetes]==${PATRONI_VERSION}" \
        "psycopg2-binary==2.9.10" \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/patroni/bin:${PATH}"

COPY k8s/build/postgres-ha/entrypoint.sh /usr/local/bin/patroni-entrypoint
RUN chmod 0755 /usr/local/bin/patroni-entrypoint

ENTRYPOINT ["/usr/local/bin/patroni-entrypoint"]
