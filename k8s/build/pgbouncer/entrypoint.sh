#!/bin/sh
set -eu

envsubst < /etc/pgbouncer/pgbouncer.ini.template > /tmp/pgbouncer.ini

write_user() {
    username="$1"
    password="$2"
    escaped_password="$(printf '%s' "$password" | sed 's/\\/\\\\/g; s/"/\\"/g')"
    printf '"%s" "%s"\n' "$username" "$escaped_password" >> /tmp/userlist.txt
}

: > /tmp/userlist.txt

if [ "$PGBOUNCER_CLUSTER" = "ticket" ]; then
    write_user ticket_user "$TICKET_DB_PASSWORD"
else
    write_user auth_user "$AUTH_DB_PASSWORD"
    write_user department_user "$DEPARTMENT_DB_PASSWORD"
    write_user brigade_user "$BRIGADE_DB_PASSWORD"
    write_user profile_user "$PROFILE_DB_PASSWORD"
    write_user location "$LOCATION_DB_PASSWORD"
    write_user routing "$ROUTING_DB_PASSWORD"
    write_user dispatch "$DISPATCH_DB_PASSWORD"
    write_user file "$FILE_DB_PASSWORD"
    write_user sla "$SLA_DB_PASSWORD"
    write_user notification "$NOTIFICATION_DB_PASSWORD"
    write_user audit "$AUDIT_DB_PASSWORD"
    write_user report "$REPORT_DB_PASSWORD"
    write_user asset "$ASSET_DB_PASSWORD"
fi

chmod 0600 /tmp/pgbouncer.ini /tmp/userlist.txt
exec pgbouncer /tmp/pgbouncer.ini
