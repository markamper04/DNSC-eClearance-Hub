"""DNSC e-Clearance Hub — Automated Drop-Folder Importer & Daily HOLD Summary (R1, R2, R14).

Scans drop_folder/ for .xml and .csv exports, verifies signed manifests via importers.py,
archives valid processed files, quarantines tampered/replayed files, writes timestamped logs,
and generates the daily per-office Students on HOLD summary report.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from importers import (
    ImportResult,
    ManifestError,
    import_accounting_csv,
    import_library_xml,
)

load_dotenv()

REPO_ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = REPO_ROOT / "schema.sql"
STARTER_STUDENTS_PATH = REPO_ROOT / "starter_kit" / "registrar_students.json"


def _setup_logger(log_file: Path, run_ts: str) -> logging.Logger:
    """Create a per-run logger writing to both log_file and stdout."""
    logger = logging.getLogger(f"dnsc.automate.{run_ts}.{id(log_file)}")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


def _close_logger(logger: logging.Logger) -> None:
    """Flush and close all handlers so temp log files can be removed cleanly on Windows."""
    for handler in list(logger.handlers):
        handler.flush()
        handler.close()
        logger.removeHandler(handler)


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Ensure SQLite tables exist using schema.sql."""
    conn.execute("PRAGMA foreign_keys = ON;")
    if SCHEMA_PATH.exists():
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))


def _load_valid_student_ids(conn: sqlite3.Connection, logger: logging.Logger) -> set[str]:
    """Load valid student IDs from SQLite students table, falling back to starter_kit JSON."""
    rows = conn.execute("SELECT student_id FROM students").fetchall()
    if rows:
        return {row[0] for row in rows}

    if STARTER_STUDENTS_PATH.exists():
        logger.info(
            "students table is empty; seeding from %s",
            STARTER_STUDENTS_PATH.name,
        )
        payload = json.loads(STARTER_STUDENTS_PATH.read_text(encoding="utf-8"))
        students = payload.get("students", [])
        conn.executemany(
            """
            INSERT OR IGNORE INTO students (student_id, name, program, year, email, registrar_status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    s["student_id"],
                    f"{s['last_name']}, {s['first_name']} {s['middle_initial']}.",
                    s["program_code"],
                    s["year_level"],
                    s["email"],
                    s["status"],
                )
                for s in students
            ],
        )
        conn.commit()
        return {s["student_id"] for s in students}

    logger.warning("No students found in SQLite or %s", STARTER_STUDENTS_PATH)
    return set()


def _move_with_manifest(src_file: Path, dest_dir: Path, prefix: str = "") -> list[Path]:
    """Move a data file and its sidecar .manifest.json (if present) into dest_dir."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    moved: list[Path] = []

    manifest_src = Path(f"{src_file}.manifest.json")
    for item in (src_file, manifest_src):
        if item.exists():
            target_name = f"{prefix}{item.name}" if prefix else item.name
            dest_path = dest_dir / target_name
            shutil.move(str(item), str(dest_path))
            moved.append(dest_path)

    return moved


def _generate_hold_summary(
    conn: sqlite3.Connection,
    logs_path: Path,
    now: datetime,
) -> tuple[Path, dict[str, int]]:
    """Query clearances for all HOLD records, write daily report, and return counts."""
    date_str = now.strftime("%Y-%m-%d")
    report_path = logs_path / f"hold_summary_{date_str}.txt"

    rows = conn.execute(
        """
        SELECT c.office, c.student_id, s.name, c.reason
        FROM clearances c
        LEFT JOIN students s ON c.student_id = s.student_id
        WHERE c.status = 'HOLD'
        ORDER BY c.office, c.student_id
        """
    ).fetchall()

    grouped: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for office, student_id, name, reason in rows:
        grouped[office].append((student_id, name or "(Unknown Name)", reason or ""))

    lines: list[str] = [
        "DNSC e-Clearance Hub — Daily Students on HOLD Summary",
        f"Report Date : {date_str}",
        f"Generated At: {now.isoformat(timespec='seconds')}",
        "=" * 72,
        "",
    ]

    hold_counts: dict[str, int] = {}
    if not grouped:
        lines.append("No students currently on HOLD.")
    else:
        for office in sorted(grouped.keys()):
            entries = grouped[office]
            hold_counts[office] = len(entries)
            lines.append(f"[{office}] Total on HOLD: {len(entries)}")
            lines.append("-" * 72)
            lines.append(f"{'Student ID':<14} {'Name':<26} Reason")
            lines.append(f"{'-' * 12:<14} {'-' * 24:<26} {'-' * 28}")
            for student_id, name, reason in entries:
                lines.append(f"{student_id:<14} {name:<26} {reason}")
            lines.append("")

    report_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return report_path, hold_counts


def run_automation(
    drop_dir: str | Path = "drop_folder",
    archive_dir: str | Path = "archive",
    quarantine_dir: str | Path = "quarantine",
    logs_dir: str | Path = "logs",
    db_path: str | Path = "eclearance.db",
    valid_student_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Run one full automated drop-folder ingestion cycle and generate the HOLD summary."""
    drop_path = Path(drop_dir)
    archive_path = Path(archive_dir)
    quarantine_path = Path(quarantine_dir)
    logs_path = Path(logs_dir)

    # Step 1: Ensure all target directories exist
    for directory in (drop_path, archive_path, quarantine_path, logs_path):
        directory.mkdir(parents=True, exist_ok=True)

    # Load HMAC secret from .env (never hardcoded)
    load_dotenv()
    hmac_key = os.getenv("MANIFEST_HMAC_KEY") or os.getenv("STARTER_HMAC_KEY") or ""

    # Step 2: Set up timestamped logging
    now = datetime.now()
    run_ts = now.strftime("%Y-%m-%d_%H%M%S")
    date_folder = now.strftime("%Y-%m-%d")
    log_file = logs_path / f"import_{run_ts}.log"
    logger = _setup_logger(log_file, run_ts)

    processed_log_path = logs_path / "processed_manifests.json"
    reject_log_path = logs_path / "rejects.log"

    archived_files: list[str] = []
    quarantined_files: list[str] = []
    import_results: list[ImportResult] = []

    conn = sqlite3.connect(db_path)
    try:
        _ensure_schema(conn)

        student_ids = (
            set(valid_student_ids)
            if valid_student_ids is not None
            else _load_valid_student_ids(conn, logger)
        )

        # Discover .xml and .csv files deterministically (ignore .manifest.json)
        data_files = sorted(
            [
                p
                for p in drop_path.iterdir()
                if p.is_file()
                and not p.name.endswith(".manifest.json")
                and p.suffix.lower() in {".xml", ".csv"}
            ],
            key=lambda p: p.name,
        )

        logger.info("Automation run started at %s", now.isoformat(timespec="seconds"))
        logger.info("Scanning folder: %s", drop_path.resolve())
        logger.info("Found %d data file(s) (.xml/.csv) to process", len(data_files))

        # Step 3: Process each file safely
        for data_file in data_files:
            ext = data_file.suffix.lower()
            logger.info("Processing %s ...", data_file.name)
            try:
                if ext == ".xml":
                    result = import_library_xml(
                        data_file,
                        conn,
                        student_ids,
                        hmac_key=hmac_key,
                        processed_log_path=processed_log_path,
                        reject_log_path=reject_log_path,
                    )
                else:
                    result = import_accounting_csv(
                        data_file,
                        conn,
                        student_ids,
                        hmac_key=hmac_key,
                        processed_log_path=processed_log_path,
                        reject_log_path=reject_log_path,
                    )

                import_results.append(result)
                logger.info(
                    "SUCCESS %s -> accepted=%d (cleared=%d, hold=%d), rejected=%d",
                    data_file.name,
                    result.accepted,
                    result.cleared,
                    result.hold,
                    result.rejected,
                )

                dest_archive = archive_path / date_folder
                _move_with_manifest(data_file, dest_archive, prefix=f"{run_ts}_")
                archived_files.append(data_file.name)
                logger.info("Archived %s (+ manifest) to %s", data_file.name, dest_archive)

            except ManifestError as exc:
                logger.error(
                    "SECURITY ALERT [%s]: %s — moving to quarantine",
                    data_file.name,
                    exc,
                )
                _move_with_manifest(data_file, quarantine_path, prefix=f"{run_ts}_")
                quarantined_files.append(data_file.name)

        # Step 4: Generate Daily "Students on HOLD" Summary per Office
        hold_summary_path, hold_counts = _generate_hold_summary(conn, logs_path, now)
        if hold_counts:
            compact = " | ".join(
                f"{office}: {count} on HOLD" for office, count in sorted(hold_counts.items())
            )
        else:
            compact = "No students currently on HOLD"

        logger.info("Daily HOLD summary written to %s", hold_summary_path)
        logger.info("HOLD Summary -> %s", compact)

        return {
            "run_ts": run_ts,
            "log_file": str(log_file),
            "hold_summary_file": str(hold_summary_path),
            "archived": archived_files,
            "quarantined": quarantined_files,
            "results": import_results,
            "hold_counts": hold_counts,
        }
    finally:
        conn.close()
        _close_logger(logger)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DNSC e-Clearance Hub — Automated drop-folder importer & HOLD summary"
    )
    parser.add_argument("--drop-dir", default="drop_folder")
    parser.add_argument("--archive-dir", default="archive")
    parser.add_argument("--quarantine-dir", default="quarantine")
    parser.add_argument("--logs-dir", default="logs")
    parser.add_argument("--db-path", default="eclearance.db")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run_automation(
        drop_dir=args.drop_dir,
        archive_dir=args.archive_dir,
        quarantine_dir=args.quarantine_dir,
        logs_dir=args.logs_dir,
        db_path=args.db_path,
    )
