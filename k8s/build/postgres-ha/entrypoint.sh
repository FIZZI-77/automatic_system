#!/bin/sh
set -eu

if [ -n "${TICKET_DB_PASSWORD:-}" ]; then
    umask 077
    printf '*:*:*:ticket_user:%s\n' "$TICKET_DB_PASSWORD" > /var/lib/postgresql/.pgpass
fi

envsubst < /etc/patroni/patroni.yaml.template > /tmp/patroni.yaml
exec patroni /tmp/patroni.yaml
