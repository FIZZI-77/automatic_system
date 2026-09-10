FROM postgres:16-alpine

RUN apk add --no-cache gettext pgbouncer

COPY k8s/build/pgbouncer/entrypoint.sh /usr/local/bin/pgbouncer-entrypoint
RUN chmod 0755 /usr/local/bin/pgbouncer-entrypoint

USER postgres
ENTRYPOINT ["/usr/local/bin/pgbouncer-entrypoint"]
