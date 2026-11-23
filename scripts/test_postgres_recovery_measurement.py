#!/usr/bin/env python3
"""Run an isolated, real PostgreSQL backup/restore and interruption drill.

This is a local integration test, not customer recovery qualification. It uses
only a locally cached PostgreSQL image pinned by digest, creates uniquely
named Podman resources, binds the source port to loopback, and removes only
resources created by this process.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
IMAGE = re.compile(r"^.+@sha256:[a-f0-9]{64}$")


class RecoveryTestError(RuntimeError):
    pass


def command(args: list[str], *, input_data: bytes | None = None, timeout: int = 60,
            env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(args, input=input_data, capture_output=True, timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RecoveryTestError("a required local command was unavailable or timed out") from error
    if result.returncode:
        raise RecoveryTestError(f"local test command failed: {Path(args[0]).name} (exit {result.returncode})")
    return result


def podman(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return command(["podman", *args], **kwargs)


def sql(container: str, database: str, statement: str) -> str:
    result = podman(["exec", "-i", container, "psql", "-U", "postgres", "-d", database,
                     "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1"], input_data=statement.encode(), timeout=120)
    return result.stdout.decode().strip()


def free_loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def parse_watermark(value: str) -> dict:
    fields = value.split("|", 2)
    if len(fields) != 3 or not fields[0].isdigit() or int(fields[0]) < 1 or not fields[1]:
        raise RecoveryTestError("database returned an invalid recovery watermark")
    try:
        committed = dt.datetime.fromisoformat(fields[2].replace("Z", "+00:00"))
    except ValueError as error:
        raise RecoveryTestError("database returned an invalid watermark timestamp") from error
    if committed.tzinfo is None:
        raise RecoveryTestError("database watermark timestamp has no timezone")
    return {"sequence": int(fields[0]), "transactionId": fields[1],
            "markerTimeUtc": committed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "_time": committed.astimezone(dt.timezone.utc)}


def latest_watermark(container: str, database: str) -> dict:
    value = sql(container, database,
                "SELECT sequence::text||'|'||transaction_id||'|'||"
                "to_char(marker_time AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') "
                "FROM m5_recovery_watermark ORDER BY sequence DESC LIMIT 1")
    return parse_watermark(value)


def ledger(container: str, database: str) -> str:
    return sql(container, database,
                "SELECT string_agg(version::text||'|'||checksum,',' ORDER BY version) FROM schema_migrations")


def payload_integrity(container: str, database: str) -> str:
    stats = sql(container, database,
                "SELECT count(*)::text||'|'||coalesce(sum(octet_length(payload)),0)::text "
                "FROM m5_recovery_payload")
    copied = podman(["exec", container, "psql", "-U", "postgres", "-d", database, "-X", "-q",
                     "-v", "ON_ERROR_STOP=1", "-c",
                     "COPY (SELECT id,payload FROM m5_recovery_payload ORDER BY id) TO STDOUT"], timeout=180)
    return stats + "|" + hashlib.sha256(copied.stdout).hexdigest()


def system_identifier(container: str) -> str:
    value = sql(container, "postgres", "SELECT system_identifier::text FROM pg_control_system()")
    if not value.isdigit():
        raise RecoveryTestError("PostgreSQL returned an invalid server identity")
    return value


def read_container_file(container: str, path: str) -> str:
    return podman(["exec", container, "cat", path]).stdout.decode().strip()


def write_container_file(container: str, path: str, content: bytes, mode: str = "600") -> None:
    parent = str(Path(path).parent)
    podman(["exec", container, "mkdir", "-p", parent])
    podman(["exec", "-i", container, "sh", "-c", f"umask 077; cat > {path}"], input_data=content)
    podman(["exec", container, "chmod", mode, path])


def start_database(name: str, alias: str, network: str, image: str,
                   owned_containers: list[str], *, port: int | None = None) -> None:
    exists = subprocess.run(["podman", "container", "exists", name], capture_output=True, timeout=10)
    if exists.returncode == 0:
        raise RecoveryTestError("a generated disposable container name already exists; refusing to touch it")
    args = ["run", "-d", "--name", name, "--network", network, "--network-alias", alias,
            "-e", "POSTGRES_HOST_AUTH_METHOD=trust"]
    if port is not None:
        args.extend(["-p", f"127.0.0.1:{port}:5432"])
    args.append(image)
    podman(args)
    # From this point onward the container is known to have been created by
    # this invocation, even if readiness fails and cleanup is needed.
    owned_containers.append(name)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = subprocess.run(["podman", "exec", name, "pg_isready", "-U", "postgres"],
                                capture_output=True, timeout=5)
        if result.returncode == 0:
            return
        time.sleep(0.25)
    raise RecoveryTestError(f"disposable PostgreSQL container {alias} did not become ready")


def prepare_database(container: str, database: str) -> None:
    podman(["exec", container, "createdb", "-U", "postgres", database])


def copy_recovery_tools(source: str) -> None:
    podman(["exec", source, "mkdir", "-p", "/opt/kordex/scripts", "/opt/kordex/control-plane"])
    podman(["cp", str(ROOT / "scripts/backup-postgres.sh"), f"{source}:/opt/kordex/scripts/backup-postgres.sh"])
    podman(["cp", str(ROOT / "scripts/restore-drill.sh"), f"{source}:/opt/kordex/scripts/restore-drill.sh"])
    podman(["cp", str(ROOT / "control-plane/migrations"), f"{source}:/opt/kordex/control-plane/"])


def restore_command(source: str, archive: str, restore_service: str, *, path: str | None = None) -> list[str]:
    args = ["exec", "-e", "PGSERVICEFILE=/root/pg_service.conf", "-e", "KORDEX_SOURCE_SERVICE=source",
            "-e", f"KORDEX_RESTORE_SERVICE={restore_service}"]
    if path is not None:
        args.extend(["-e", f"PATH={path}"])
    args.extend([source, "bash", "-eu", "-c",
                 f"cd /opt/kordex; bash scripts/restore-drill.sh {archive}"])
    return ["podman", *args]


def restore_summary(output: str) -> dict:
    values = {}
    for name in ("restore_started_at_utc", "restore_completed_at_utc", "restore_duration_seconds"):
        match = re.search(rf"(?m)^{name}=([^\s]+)$", output)
        if not match:
            raise RecoveryTestError("restore script omitted a required measurement")
        values[name] = match.group(1)
    return values


def insert_post_backup_watermark(source: str) -> None:
    sql(source, "kordex", "INSERT INTO m5_recovery_watermark DEFAULT VALUES")


def run_interrupted_restore(source: str, interrupt_target: str, archive: str, report: dict) -> None:
    wrapper = ("#!/usr/bin/env bash\nset -euo pipefail\n"
               "if [[ ${1:-} == --list ]]; then exec /usr/local/bin/pg_restore \"$@\"; fi\n"
               "printf '%s\\n' \"$$\" > /root/m5-interrupted-pg-restore.pid\n"
               "exec /usr/local/bin/pg_restore \"$@\"\n")
    write_container_file(source, "/root/m5-interruption-bin/pg_restore", wrapper.encode(), "700")
    log = "/root/m5-interrupted-restore.log"
    pid_file = "/root/m5-interrupted-pg-restore.pid"
    podman(["exec", source, "rm", "-f", log, pid_file])
    command_args = restore_command(source, archive, "interrupted",
                                   path="/root/m5-interruption-bin:/usr/local/bin:/usr/bin:/bin")
    command_args[-1] = f"{command_args[-1]} > {log} 2>&1"
    process = subprocess.Popen(command_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = None
    active = False
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and process.poll() is None:
            pid_result = subprocess.run(["podman", "exec", source, "cat", pid_file], capture_output=True, timeout=5)
            if pid_result.returncode == 0:
                raw_pid = pid_result.stdout.decode().strip()
                if raw_pid.isdigit():
                    pid = raw_pid
                    active_sql = ("SELECT count(*) FROM pg_stat_activity WHERE datname='kordex_interrupted' "
                                  "AND state='active' AND pid<>pg_backend_pid()")
                    activity = sql(interrupt_target, "postgres", active_sql)
                    if activity.isdigit() and int(activity) > 0:
                        active = True
                        break
            time.sleep(0.1)
        if not active or pid is None:
            diagnostic = ""
            log_result = subprocess.run(["podman", "exec", source, "sh", "-c",
                                         f"test -f {log} && tail -n 12 {log} || true"],
                                        capture_output=True, timeout=5)
            if log_result.returncode == 0 and log_result.stdout:
                diagnostic = "; restore output: " + log_result.stdout.decode(errors="replace")[-1200:].replace("\n", " ")
            raise RecoveryTestError("could not observe the real pg_restore transaction before interruption"
                                    f" (exit={process.poll()}, pid_recorded={pid is not None}){diagnostic}")
        podman(["exec", source, "kill", "-TERM", pid])
        try:
            exit_code = process.wait(timeout=60)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait(timeout=10)
            raise RecoveryTestError("interrupted restore process did not exit") from error
        log_text = read_container_file(source, log)
        cleanup_deadline = time.monotonic() + 30
        active_after = "1"
        while time.monotonic() < cleanup_deadline:
            active_after = sql(interrupt_target, "postgres",
                               "SELECT count(*) FROM pg_stat_activity WHERE datname='kordex_interrupted' "
                               "AND state='active' AND pid<>pg_backend_pid()")
            if active_after == "0":
                break
            time.sleep(0.1)
        if active_after != "0":
            raise RecoveryTestError("interrupted pg_restore still has an active database session")
        user_relations = sql(interrupt_target, "kordex_interrupted",
                             "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                             "WHERE n.nspname NOT IN ('pg_catalog','information_schema') "
                             "AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','v','m','S','f')")
        succeeded = "Restore drill succeeded" in log_text
        if exit_code == 0 or succeeded or user_relations != "0":
            raise RecoveryTestError("interrupted restore was reported successful or left partial target objects")
        report["interruptedRestore"] = {
            "signal": "SIGTERM", "restoreProcessObservedActive": True, "processExitCode": exit_code,
            "successReported": succeeded, "targetUserRelationsAfterRollback": int(user_relations),
            "result": "PASS",
        }
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def perform(image: str) -> dict:
    if not IMAGE.fullmatch(image):
        raise RecoveryTestError("PostgreSQL image must be pinned by SHA-256 digest")
    if shutil.which("podman") is None or shutil.which("go") is None:
        raise RecoveryTestError("Podman and Go are required locally")
    if subprocess.run(["podman", "image", "exists", image], capture_output=True).returncode != 0:
        raise RecoveryTestError("the exact pinned PostgreSQL image is not present locally; the test will not pull it")

    token = uuid.uuid4().hex[:12]
    network = f"kordex-m5-{token}-network"
    containers = [f"kordex-m5-{token}-source", f"kordex-m5-{token}-restore", f"kordex-m5-{token}-interrupt"]
    aliases = ["source", "restore", "interrupted"]
    databases = ["kordex", "kordex_restore", "kordex_interrupted"]
    owned_containers: list[str] = []
    owns_network = False
    report: dict = {"schemaVersion": 1, "kind": "kordex-local-postgres-recovery-measurement",
                    "scope": "local disposable PostgreSQL only", "postgresImage": image, "result": "FAIL"}
    try:
        exists = subprocess.run(["podman", "network", "exists", network], capture_output=True, timeout=10)
        if exists.returncode == 0:
            raise RecoveryTestError("a generated disposable network name already exists; refusing to touch it")
        podman(["network", "create", network])
        owns_network = True
        source_port = free_loopback_port()
        start_database(containers[0], aliases[0], network, image, owned_containers, port=source_port)
        for name, alias in zip(containers[1:], aliases[1:]):
            start_database(name, alias, network, image, owned_containers)
        for name, database in zip(containers, databases):
            prepare_database(name, database)

        migrate_env = os.environ.copy()
        migrate_env.update({"DATABASE_URL": f"postgres://postgres@127.0.0.1:{source_port}/kordex?sslmode=disable",
                            "KORDEX_LOCAL_DEVELOPMENT": "true", "KORDEX_ADMIN_TOKEN": uuid.uuid4().hex * 2,
                            "KORDEX_LISTEN_ADDRESS": "127.0.0.1:0", "KORDEX_METRICS_LISTEN_ADDRESS": "127.0.0.1:0"})
        migration = command(["go", "run", "./control-plane/cmd/kordex", "-migrate"], env=migrate_env, timeout=180)
        migration_stdout = migration.stdout.decode(errors="replace")
        if "database migrations complete" not in migration_stdout:
            raise RecoveryTestError("application migration command did not confirm completion")
        report["sourceDatabaseIdentity"] = system_identifier(containers[0])
        report["restoreTargetIdentity"] = system_identifier(containers[1])
        report["interruptedTargetIdentity"] = system_identifier(containers[2])
        report["postgresVersion"] = sql(containers[0], "postgres", "SELECT current_setting('server_version')")
        if len({report["sourceDatabaseIdentity"], report["restoreTargetIdentity"],
                report["interruptedTargetIdentity"]}) != 3:
            raise RecoveryTestError("disposable PostgreSQL servers do not have distinct identities")

        seed_sql = ("CREATE TABLE m5_recovery_watermark (sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, "
                    "transaction_id text NOT NULL DEFAULT pg_current_xact_id()::text, "
                    "marker_time timestamptz NOT NULL DEFAULT clock_timestamp());\n"
                    "INSERT INTO m5_recovery_watermark DEFAULT VALUES;\n"
                    "CREATE TABLE m5_recovery_payload (id bigint PRIMARY KEY, payload text NOT NULL);\n"
                    "INSERT INTO m5_recovery_payload(id,payload) "
                    "SELECT g, string_agg(md5(g::text||':'||n::text),'' ORDER BY n) "
                    "FROM generate_series(1,32768) g CROSS JOIN generate_series(1,64) n GROUP BY g;")
        sql(containers[0], "kordex", seed_sql)
        initial = latest_watermark(containers[0], "kordex")
        report["sourceWatermarkAtBackup"] = {key: value for key, value in initial.items() if key != "_time"}

        copy_recovery_tools(containers[0])
        service_file = ("[source]\nhost=127.0.0.1\nport=5432\ndbname=kordex\nuser=postgres\nsslmode=disable\n\n"
                        "[restore]\nhost=restore\ndbname=kordex_restore\nuser=postgres\nsslmode=disable\n\n"
                        "[interrupted]\nhost=interrupted\ndbname=kordex_interrupted\nuser=postgres\nsslmode=disable\n")
        write_container_file(containers[0], "/root/pg_service.conf", service_file.encode())
        podman(["exec", containers[0], "mkdir", "-p", "/root/backups"])
        podman(["exec", containers[0], "chmod", "700", "/root/backups"])
        backup_result = podman(["exec", "-e", "PGSERVICEFILE=/root/pg_service.conf", "-e", "PGSERVICE=source",
                                "-e", "KORDEX_BACKUP_DIR=/root/backups", containers[0], "bash", "-eu", "-c",
                                "cd /opt/kordex; bash scripts/backup-postgres.sh"])
        backup_output = backup_result.stdout.decode(errors="replace")
        match = re.search(r"(?m)^Backup complete: (\S+)$", backup_output)
        if not match:
            raise RecoveryTestError("backup command did not return its archive identity")
        archive = match.group(1)
        checksum_text = podman(["exec", containers[0], "sha256sum", archive]).stdout.decode().split()
        if len(checksum_text) < 1 or not re.fullmatch(r"[a-f0-9]{64}", checksum_text[0]):
            raise RecoveryTestError("backup archive checksum is unavailable or invalid")
        manifest_text = read_container_file(containers[0], archive + ".manifest")
        manifest = dict(line.split("=", 1) for line in manifest_text.splitlines() if "=" in line)
        if manifest.get("sha256") != checksum_text[0] or manifest.get("archive") != Path(archive).name:
            raise RecoveryTestError("backup manifest does not bind the actual archive checksum and name")
        report["backup"] = {"identity": Path(archive).name, "sha256": checksum_text[0],
                            "createdAtUtc": manifest.get("created_at_utc"), "format": manifest.get("format"),
                            "pgDumpVersion": manifest.get("pg_dump")}

        insert_post_backup_watermark(containers[0])
        source_latest = latest_watermark(containers[0], "kordex")
        report["sourceWatermarkAtMeasurement"] = {key: value for key, value in source_latest.items() if key != "_time"}

        restore_result = podman(["exec", "-e", "PGSERVICEFILE=/root/pg_service.conf", "-e", "KORDEX_SOURCE_SERVICE=source",
                                 "-e", "KORDEX_RESTORE_SERVICE=restore", containers[0], "bash", "-eu", "-c",
                                 f"cd /opt/kordex; bash scripts/restore-drill.sh {archive}"], timeout=180)
        restore_output = restore_result.stdout.decode(errors="replace")
        restore_measurement = restore_summary(restore_output)
        recovered_latest = latest_watermark(containers[1], "kordex_restore")
        source_state = sql(containers[0], "kordex",
                           "SELECT count(*)::text||'|'||min(sequence)::text||'|'||max(sequence)::text FROM m5_recovery_watermark")
        recovered_state = sql(containers[1], "kordex_restore",
                              "SELECT count(*)::text||'|'||min(sequence)::text||'|'||max(sequence)::text FROM m5_recovery_watermark")
        source_payload = payload_integrity(containers[0], "kordex")
        recovered_payload = payload_integrity(containers[1], "kordex_restore")
        source_ledger = ledger(containers[0], "kordex")
        recovered_ledger = ledger(containers[1], "kordex_restore")
        sequence_gap = source_latest["sequence"] - recovered_latest["sequence"]
        gap_is_valid = (source_state == f"{source_latest['sequence']}|1|{source_latest['sequence']}"
                        and recovered_state == f"{recovered_latest['sequence']}|1|{recovered_latest['sequence']}"
                        and recovered_latest["sequence"] <= source_latest["sequence"])
        if not gap_is_valid:
            raise RecoveryTestError("source and recovered watermark ranges are not contiguous; gap is not measurable")
        gap_seconds = (source_latest["_time"] - recovered_latest["_time"]).total_seconds()
        if sequence_gap < 0 or gap_seconds < 0:
            raise RecoveryTestError("recovered watermark is newer than source measurement")
        if (source_payload != recovered_payload or source_ledger != recovered_ledger
                or recovered_latest["sequence"] != initial["sequence"]):
            raise RecoveryTestError("restored payload, migration ledger, or recovery watermark differs")
        report["restoredMigrationLedger"] = {"entries": len(source_ledger.split(",")),
                                              "versionsAndChecksums": [
                                                  {"version": int(entry.split("|", 1)[0]),
                                                   "sha256": entry.split("|", 1)[1]}
                                                  for entry in source_ledger.split(",")],
                                              "sourceMatchesRestored": source_ledger == recovered_ledger}
        count, total_bytes, digest = recovered_payload.split("|", 2)
        report["dataIntegrity"] = {"payloadRows": int(count), "payloadBytes": int(total_bytes),
                                   "orderedPayloadDigest": digest, "sourceMatchesRestored": True}
        report["recoveredWatermark"] = {key: value for key, value in recovered_latest.items() if key != "_time"}
        report["recoveryPointGap"] = {"valid": True, "watermarkSequenceDifference": sequence_gap,
                                      "secondsBetweenLatestCommittedMarkers": round(gap_seconds, 6),
                                      "interpretation": "controlled local gap between visible transaction watermarks; not a production RPO"}
        report["restore"] = restore_measurement
        report["successfulRestoreTarget"] = containers[1]

        run_interrupted_restore(containers[0], containers[2], archive, report)
        report["result"] = "PASS"
        return report
    finally:
        removed_containers = []
        for name in owned_containers:
            podman(["rm", "-f", name], timeout=30)
            exists = subprocess.run(["podman", "container", "exists", name], capture_output=True, timeout=10)
            if exists.returncode == 0:
                raise RecoveryTestError("a disposable container created by the test remains after cleanup")
            removed_containers.append(name)
        removed_network = False
        if owns_network:
            podman(["network", "rm", network], timeout=30)
            exists = subprocess.run(["podman", "network", "exists", network], capture_output=True, timeout=10)
            if exists.returncode == 0:
                raise RecoveryTestError("the disposable network created by the test remains after cleanup")
            removed_network = True
        report["cleanup"] = {"removedContainers": removed_containers, "removedNetwork": removed_network,
                             "preexistingResourcesTouched": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-image", required=True, help="locally cached PostgreSQL image reference pinned by SHA-256 digest")
    parser.add_argument("--report", type=Path, help="optional new mode-0600 JSON report path; existing paths are refused")
    args = parser.parse_args()
    try:
        report = perform(args.postgres_image)
    except Exception as error:
        report = {"schemaVersion": 1, "kind": "kordex-local-postgres-recovery-measurement",
                  "scope": "local disposable PostgreSQL only", "result": "FAIL",
                  "failure": str(error) if isinstance(error, RecoveryTestError) else "unexpected local test failure"}
        print(json.dumps(report, sort_keys=True, indent=2))
        return 1
    rendered = json.dumps(report, sort_keys=True, indent=2)
    print(rendered)
    if args.report:
        try:
            fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(rendered + "\n")
        except OSError:
            print("could not create a new private report file", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
