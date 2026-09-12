#!/usr/bin/env python3

import argparse
import json
import subprocess
from pathlib import Path


APPLICATIONS = [
    ("api-gateway", "automatic-system-api-gateway", ".", "API_Gateway/Dockerfile", "API_Gateway/"),
    ("auth", "automatic-system-auth", "Auth_Service", "Auth_Service/Dockerfile", "Auth_Service/"),
    ("ticket", "automatic-system-ticket", "Ticket_Service", "Ticket_Service/Dockerfile", "Ticket_Service/"),
    ("department", "automatic-system-department", "Department_Service", "Department_Service/Dockerfile", "Department_Service/"),
    ("brigade", "automatic-system-brigade", "Brigade_Service", "Brigade_Service/Dockerfile", "Brigade_Service/"),
    ("profile", "automatic-system-profile", "Profile_Service", "Profile_Service/Dockerfile", "Profile_Service/"),
    ("location", "automatic-system-location", "Location_Service", "Location_Service/Dockerfile", "Location_Service/"),
    ("routing", "automatic-system-routing", "Routing_Service", "Routing_Service/Dockerfile", "Routing_Service/"),
    ("dispatch", "automatic-system-dispatch", ".", "Dispatch_Service/Dockerfile", "Dispatch_Service/"),
    ("file", "automatic-system-file", "File_Service", "File_Service/Dockerfile", "File_Service/"),
    ("sla", "automatic-system-sla", ".", "SLA_Service/Dockerfile", "SLA_Service/"),
    ("notification", "automatic-system-notification", ".", "Notification_Service/Dockerfile", "Notification_Service/"),
    ("audit", "automatic-system-audit", ".", "Audit_Service/Dockerfile", "Audit_Service/"),
    ("analytics", "automatic-system-analytics", ".", "Analytics_Service/Dockerfile", "Analytics_Service/"),
    ("report", "automatic-system-report", ".", "Report_Service/Dockerfile", "Report_Service/"),
    ("asset", "automatic-system-asset", ".", "Asset_Service/Dockerfile", "Asset_Service/"),
    ("transponder-simulator", "automatic-system-transponder-simulator", "Transponder_Simulator", "Transponder_Simulator/Dockerfile", "Transponder_Simulator/"),
    ("postgres-ha", "automatic-system-postgres-ha", ".", "k8s/build/postgres-ha/Dockerfile", "k8s/build/postgres-ha/"),
    ("postgres-citus-ha", "automatic-system-postgres-citus-ha", ".", "k8s/build/postgres-citus-ha/Dockerfile", "k8s/build/postgres-citus-ha/"),
    ("pgbouncer", "automatic-system-pgbouncer", ".", "k8s/build/pgbouncer/Dockerfile", "k8s/build/pgbouncer/"),
]

MIGRATORS = [
    ("auth", "automatic-system-auth-migrator", "Auth_Service"),
    ("ticket", "automatic-system-ticket-migrator", "Ticket_Service"),
    ("department", "automatic-system-department-migrator", "Department_Service"),
    ("brigade", "automatic-system-brigade-migrator", "Brigade_Service"),
    ("profile", "automatic-system-profile-migrator", "Profile_Service"),
    ("location", "automatic-system-location-migrator", "Location_Service"),
    ("routing", "automatic-system-routing-migrator", "Routing_Service"),
    ("dispatch", "automatic-system-dispatch-migrator", "Dispatch_Service"),
    ("file", "automatic-system-file-migrator", "File_Service"),
    ("sla", "automatic-system-sla-migrator", "SLA_Service"),
    ("notification", "automatic-system-notification-migrator", "Notification_Service"),
    ("audit", "automatic-system-audit-migrator", "Audit_Service"),
    ("report", "automatic-system-report-migrator", "Report_Service"),
    ("asset", "automatic-system-asset-migrator", "Asset_Service"),
]

CANARIES = {
    "api-gateway": "api-gateway",
    "auth": "auth-service",
    "ticket": "ticket-service",
    "department": "department-service",
    "brigade": "brigade-service",
    "profile": "profile-service",
    "location": "location-service",
    "routing": "routing-service",
    "dispatch": "dispatch-service",
    "file": "file-service",
    "sla": "sla-service",
    "notification": "notification-service",
    "audit": "audit-service",
    "analytics": "analytics-service",
    "report": "report-service",
    "asset": "asset-service",
    "frontend": "frontend",
}


def changed_files(base: str, head: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", base, head],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()]


def starts_with_any(paths: list[str], prefixes: tuple[str, ...]) -> bool:
    return any(path.startswith(prefixes) for path in paths)


def application_matrix(names: set[str]) -> list[dict[str, object]]:
    result = [
        {
            "service": service,
            "package": package,
            "context": context,
            "dockerfile": dockerfile,
            "enabled": True,
        }
        for service, package, context, dockerfile, _ in APPLICATIONS
        if service in names
    ]
    return result or [{"service": "none", "package": "none", "context": ".", "dockerfile": "Dockerfile", "enabled": False}]


def migrator_matrix(names: set[str]) -> list[dict[str, object]]:
    result = [
        {"service": service, "package": package, "context": context, "enabled": True}
        for service, package, context in MIGRATORS
        if service in names
    ]
    return result or [{"service": "none", "package": "none", "context": ".", "enabled": False}]


def write_output(name: str, value: object, output_file: Path | None) -> None:
    encoded = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    print(f"{name}={encoded}")
    if output_file:
        with output_file.open("a", encoding="utf-8") as stream:
            stream.write(f"{name}={encoded}\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--force-all", action="store_true")
    parser.add_argument("--changed-file", action="append")
    parser.add_argument("--output-file", type=Path)
    args = parser.parse_args()

    paths = args.changed_file if args.changed_file is not None else (
        [] if args.force_all else changed_files(args.base, args.head)
    )
    force_all = args.force_all

    applications = {
        service
        for service, _, _, _, prefix in APPLICATIONS
        if force_all or starts_with_any(paths, (prefix,))
    }
    migrators = {
        service
        for service, _, context in MIGRATORS
        if force_all or starts_with_any(paths, (f"{context}/scheme/",))
    }

    if force_all or "k8s/build/Dockerfile.migrator" in paths:
        migrators = {service for service, _, _ in MIGRATORS}

    frontend = force_all or starts_with_any(paths, ("Frontend/",))
    clickhouse_init = force_all or "k8s/build/Dockerfile.clickhouse-init" in paths or starts_with_any(
        paths, ("Analytics_Service/scheme/",)
    )

    deployed_applications = sorted((applications & CANARIES.keys()) | ({"frontend"} if frontend else set()))
    canaries = [CANARIES[name] for name in deployed_applications]

    write_output("application_matrix", application_matrix(applications), args.output_file)
    write_output("migrator_matrix", migrator_matrix(migrators), args.output_file)
    write_output("frontend_changed", str(frontend).lower(), args.output_file)
    write_output("clickhouse_init_changed", str(clickhouse_init).lower(), args.output_file)
    write_output("deployed_applications", deployed_applications, args.output_file)
    write_output("migrator_services", sorted(migrators), args.output_file)
    write_output("changed_canaries", canaries, args.output_file)


if __name__ == "__main__":
    main()
