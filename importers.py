"""DNSC e-Clearance Hub — Library XML & Accounting CSV Importers (R9, R11, R13, R14).

Validates signed drop-folder manifests before parsing, enforces allow-list rules
matching docs/mapping_spec.md, logs structured rejects, and performs parameterized
SQLite upserts into the clearances table.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import os
import re
import sqlite3
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Step 1: Environment & Default Paths (R13)
# ---------------------------------------------------------------------------
DEFAULT_HMAC_KEY = os.getenv("MANIFEST_HMAC_KEY") or os.getenv("STARTER_HMAC_KEY") or ""
DEFAULT_PROCESSED_MANIFESTS_PATH = Path("logs/processed_manifests.json")
DEFAULT_REJECT_LOG_PATH = Path("logs/rejects.log")

# ---------------------------------------------------------------------------
# Step 2: Allow-Lists & Result Structure (R11)
# ---------------------------------------------------------------------------
STUDENT_ID_RE = re.compile(r"^\d{4}-\d{5}$")
NAME_RE = re.compile(r"^[A-Z][A-Z\s'-]+,\s[A-Za-z][A-Za-z\s'-]+\s[A-Z]\.$")
NUMERIC_RE = re.compile(r"^\d+(\.\d{1,2})?$")
INT_RE = re.compile(r"^\d+$")

# Valid DNSC programs from registrar_students.json + Library XML program aliases
# (BSHM is intentionally excluded and rejected with ERR_INVALID_PROGRAM).
PROGRAM_ALIASES: dict[str, str] = {
    "BSA": "AGRI",
    "BSCRIM": "CRIM",
    "BSED-MATH": "EDMATH",
    "BSIS": "IS",
    "BSIT": "IT",
    "AGRI": "AGRI",
    "CRIM": "CRIM",
    "EDMATH": "EDMATH",
    "IS": "IS",
    "IT": "IT",
}
ALLOWED_PROGRAMS: set[str] = set(PROGRAM_ALIASES.keys())


class ManifestError(Exception):
    """Raised when pre-import R14 manifest verification or replay protection fails."""


@dataclass
class ImportResult:
    """Consistent return object for both XML and CSV importers."""

    source_file: str
    accepted: int = 0
    cleared: int = 0
    hold: int = 0
    rejected: int = 0
    rejects: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Step 3: Pre-Import Security Gate — verify_manifest() + Replay Check (R14)
# ---------------------------------------------------------------------------
def _load_processed_manifests(processed_path: Path) -> set[str]:
    if not processed_path.exists():
        return set()
    try:
        with processed_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return {str(item) for item in data}
    except (OSError, json.JSONDecodeError):
        return set()
    return set()


def _record_processed_manifest(signature: str, processed_path: Path) -> None:
    processed = _load_processed_manifests(processed_path)
    processed.add(signature)
    processed_path.parent.mkdir(parents=True, exist_ok=True)
    with processed_path.open("w", encoding="utf-8") as fh:
        json.dump(sorted(processed), fh, indent=2)


def verify_manifest(
    file_path: str | Path,
    hmac_key: str | None = None,
    processed_log_path: str | Path = DEFAULT_PROCESSED_MANIFESTS_PATH,
) -> dict[str, Any]:
    """Verify sidecar .manifest.json HMAC signature, file SHA-256 hash, and replay state.

    Must execute before opening any XML or CSV file for row-level parsing.
    Returns the parsed manifest dictionary (including its verified signature).
    """
    target = Path(file_path)
    manifest_path = Path(f"{target}.manifest.json")

    if not target.exists():
        raise ManifestError(f"Target import file not found: {target}")
    if not manifest_path.exists():
        raise ManifestError(f"Missing manifest file: {manifest_path}")

    secret_key = hmac_key if hmac_key is not None else (
        os.getenv("MANIFEST_HMAC_KEY") or os.getenv("STARTER_HMAC_KEY") or ""
    )
    if not secret_key:
        raise ManifestError("MANIFEST_HMAC_KEY is not configured in environment")

    try:
        with manifest_path.open("r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"Invalid manifest JSON: {exc}") from exc

    manifest_sig = manifest.get("signature")
    if not isinstance(manifest_sig, str) or not manifest_sig:
        raise ManifestError("Manifest is missing required 'signature' field")

    # 1. Verify HMAC-SHA256 signature using constant-time comparison
    canonical_body = json.dumps(
        {k: v for k, v in manifest.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected_manifest_sig = hmac.new(
        secret_key.encode("utf-8"), canonical_body, hashlib.sha256
    ).hexdigest()

    raw_bytes = target.read_bytes()
    expected_raw_sig = hmac.new(
        secret_key.encode("utf-8"), raw_bytes, hashlib.sha256
    ).hexdigest()

    # Support starter_kit signed-manifest format (canonical JSON + file sha256)
    # as well as direct raw-byte HMAC manifests.
    if hmac.compare_digest(expected_manifest_sig, manifest_sig):
        expected_hash = manifest.get("sha256")
        if not isinstance(expected_hash, str) or not expected_hash:
            raise ManifestError("Manifest is missing required 'sha256' field")
        actual_hash = hashlib.sha256(raw_bytes).hexdigest()
        lf_hash = hashlib.sha256(raw_bytes.replace(b"\r\n", b"\n")).hexdigest()
        if not (
            hmac.compare_digest(actual_hash, expected_hash)
            or hmac.compare_digest(lf_hash, expected_hash)
        ):
            raise ManifestError("Tampered file or invalid signature (file hash mismatch)")
    elif not hmac.compare_digest(expected_raw_sig, manifest_sig):
        raise ManifestError("Tampered file or invalid signature")

    # 2. Replay protection check
    processed = _load_processed_manifests(Path(processed_log_path))
    if manifest_sig in processed:
        raise ManifestError("Replay detected: file already imported")

    return manifest


# ---------------------------------------------------------------------------
# Step 4: Shared Reject Logger (R9)
# ---------------------------------------------------------------------------
def log_reject(
    rejects_list: list[dict[str, Any]],
    source_file: str,
    row_ref: int | str | None,
    raw_id: str,
    error_code: str,
    reason: str,
    reject_log_path: str | Path = DEFAULT_REJECT_LOG_PATH,
) -> dict[str, Any]:
    """Append a structured reject entry to memory and write a JSONL line to disk."""
    entry = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "source_file": os.path.basename(str(source_file)),
        "row_index": row_ref,
        "student_id_raw": raw_id,
        "error_code": error_code,
        "reason": reason,
    }
    rejects_list.append(entry)

    log_path = Path(reject_log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return entry


# ---------------------------------------------------------------------------
# Step 5: Parameterized SQLite Upsert Helper (R13)
# ---------------------------------------------------------------------------
def upsert_clearance(
    conn: sqlite3.Connection,
    student_id: str,
    office: str,
    status: str,
    reason: str,
    updated_by: str,
) -> None:
    """Insert or update a student's clearance record using parameterized SQL."""
    conn.execute(
        """
        INSERT INTO clearances (student_id, office, status, reason, updated_by, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(student_id, office) DO UPDATE SET
            status = excluded.status,
            reason = excluded.reason,
            updated_by = excluded.updated_by,
            updated_at = excluded.updated_at
        """,
        (
            student_id,
            office,
            status,
            reason,
            updated_by,
            datetime.now().isoformat(timespec="seconds"),
        ),
    )


# ---------------------------------------------------------------------------
# Step 6: Library XML Importer
# ---------------------------------------------------------------------------
def import_library_xml(
    xml_path: str | Path,
    conn: sqlite3.Connection,
    valid_student_ids: set[str],
    hmac_key: str | None = None,
    processed_log_path: str | Path = DEFAULT_PROCESSED_MANIFESTS_PATH,
    reject_log_path: str | Path = DEFAULT_REJECT_LOG_PATH,
) -> ImportResult:
    """Verify, validate, and import a Library XML export into clearances."""
    xml_file = Path(xml_path)
    manifest = verify_manifest(xml_file, hmac_key=hmac_key, processed_log_path=processed_log_path)

    result = ImportResult(source_file=xml_file.name)
    tree = ET.parse(xml_file)
    root = tree.getroot()

    seen_cards: set[str] = set()
    seen_students: set[str] = set()

    for idx, borrower in enumerate(root.findall("borrower"), start=1):
        card_no = (borrower.get("card") or "").strip()
        student_id = (borrower.findtext("studentNo") or "").strip()
        name = (borrower.findtext("name") or "").strip()
        program = (borrower.findtext("program") or "").strip().upper()
        last_borrowed = (borrower.findtext("lastBorrowed") or "").strip()
        unreturned_str = (borrower.findtext("unreturnedBooks") or "").strip()
        fine_str = (borrower.findtext("unpaidFines") or "").strip()

        # 1. Bad ID
        if not STUDENT_ID_RE.match(student_id):
            log_reject(
                result.rejects,
                xml_file.name,
                idx,
                student_id,
                "ERR_BAD_ID",
                f"Malformed studentNo '{student_id}' (card={card_no})",
                reject_log_path=reject_log_path,
            )
            result.rejected += 1
            continue

        # 2. Unknown student
        if student_id not in valid_student_ids:
            log_reject(
                result.rejects,
                xml_file.name,
                idx,
                student_id,
                "ERR_UNKNOWN_STUDENT",
                f"Student ID '{student_id}' not found in Registrar masterlist",
                reject_log_path=reject_log_path,
            )
            result.rejected += 1
            continue

        # 3. Bad name format
        if not NAME_RE.match(name):
            log_reject(
                result.rejects,
                xml_file.name,
                idx,
                student_id,
                "ERR_BAD_NAME",
                f"Invalid name format '{name}' (expected 'LAST, First M.')",
                reject_log_path=reject_log_path,
            )
            result.rejected += 1
            continue

        # 4. Invalid program
        if program not in ALLOWED_PROGRAMS:
            log_reject(
                result.rejects,
                xml_file.name,
                idx,
                student_id,
                "ERR_INVALID_PROGRAM",
                f"Program '{program}' is not in the Registrar allow-list",
                reject_log_path=reject_log_path,
            )
            result.rejected += 1
            continue

        # 5. Duplicate card / duplicate borrower in same XML batch
        if not card_no or card_no in seen_cards or student_id in seen_students:
            log_reject(
                result.rejects,
                xml_file.name,
                idx,
                student_id,
                "ERR_DUPLICATE_CARD",
                f"Duplicate library card '{card_no}' or student '{student_id}' in batch",
                reject_log_path=reject_log_path,
            )
            result.rejected += 1
            continue

        # 6. Impossible / invalid date (Library XML uses MM/DD/YYYY)
        try:
            datetime.strptime(last_borrowed, "%m/%d/%Y")
        except ValueError:
            log_reject(
                result.rejects,
                xml_file.name,
                idx,
                student_id,
                "ERR_INVALID_DATE",
                f"Invalid calendar date in <lastBorrowed>: '{last_borrowed}'",
                reject_log_path=reject_log_path,
            )
            result.rejected += 1
            continue

        # 7. Negative / invalid fine
        if not NUMERIC_RE.match(fine_str):
            log_reject(
                result.rejects,
                xml_file.name,
                idx,
                student_id,
                "ERR_NEGATIVE_FINE",
                f"Invalid or negative fine in <unpaidFines>: '{fine_str}'",
                reject_log_path=reject_log_path,
            )
            result.rejected += 1
            continue
        fine = float(fine_str)
        if fine < 0:
            log_reject(
                result.rejects,
                xml_file.name,
                idx,
                student_id,
                "ERR_NEGATIVE_FINE",
                f"Negative fine in <unpaidFines>: '{fine_str}'",
                reject_log_path=reject_log_path,
            )
            result.rejected += 1
            continue

        # 8. Unreturned books count
        if not INT_RE.match(unreturned_str):
            log_reject(
                result.rejects,
                xml_file.name,
                idx,
                student_id,
                "ERR_NON_NUMERIC_AMOUNT",
                f"Invalid <unreturnedBooks> value: '{unreturned_str}'",
                reject_log_path=reject_log_path,
            )
            result.rejected += 1
            continue
        unreturned_books = int(unreturned_str)

        seen_cards.add(card_no)
        seen_students.add(student_id)

        # Compute status & reason
        if unreturned_books == 0 and fine == 0.0:
            status = "CLEARED"
            reason = ""
            result.cleared += 1
        else:
            status = "HOLD"
            parts: list[str] = []
            if unreturned_books > 0:
                parts.append(f"{unreturned_books} unreturned book(s)")
            if fine > 0.0:
                parts.append(f"unpaid fine of PHP {fine:.2f}")
            reason = "; ".join(parts)
            result.hold += 1

        upsert_clearance(conn, student_id, "Library", status, reason, "importer:library")
        result.accepted += 1

    conn.commit()
    _record_processed_manifest(manifest["signature"], Path(processed_log_path))
    return result


# ---------------------------------------------------------------------------
# Step 7: Accounting CSV Importer
# ---------------------------------------------------------------------------
def import_accounting_csv(
    csv_path: str | Path,
    conn: sqlite3.Connection,
    valid_student_ids: set[str],
    hmac_key: str | None = None,
    processed_log_path: str | Path = DEFAULT_PROCESSED_MANIFESTS_PATH,
    reject_log_path: str | Path = DEFAULT_REJECT_LOG_PATH,
) -> ImportResult:
    """Verify, validate, and import an Accounting CSV export into clearances."""
    csv_file = Path(csv_path)
    manifest = verify_manifest(csv_file, hmac_key=hmac_key, processed_log_path=processed_log_path)

    result = ImportResult(source_file=csv_file.name)

    with csv_file.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if not header:
            return result

        col_index = {name.strip(): i for i, name in enumerate(header)}
        expected_cols = len(header)
        seen_students: set[str] = set()

        for row_num, row in enumerate(reader, start=2):
            raw_id = row[0].strip() if row else ""

            # 1. Corrupted row (missing or extra columns)
            if len(row) != expected_cols:
                log_reject(
                    result.rejects,
                    csv_file.name,
                    row_num,
                    raw_id,
                    "ERR_CORRUPTED_ROW",
                    f"Expected {expected_cols} columns, got {len(row)}",
                    reject_log_path=reject_log_path,
                )
                result.rejected += 1
                continue

            student_id = row[col_index["StudentNo"]].strip()
            balance_str = row[col_index["Balance"]].strip()
            date_str = row[col_index["LastPaymentDate"]].strip()

            # 2. Bad ID
            if not STUDENT_ID_RE.match(student_id):
                log_reject(
                    result.rejects,
                    csv_file.name,
                    row_num,
                    student_id,
                    "ERR_BAD_ID",
                    f"Malformed StudentNo '{student_id}'",
                    reject_log_path=reject_log_path,
                )
                result.rejected += 1
                continue

            # 3. Unknown student
            if student_id not in valid_student_ids:
                log_reject(
                    result.rejects,
                    csv_file.name,
                    row_num,
                    student_id,
                    "ERR_UNKNOWN_STUDENT",
                    f"Student ID '{student_id}' not found in Registrar masterlist",
                    reject_log_path=reject_log_path,
                )
                result.rejected += 1
                continue

            # 3b. Duplicate student in same CSV batch
            if student_id in seen_students:
                log_reject(
                    result.rejects,
                    csv_file.name,
                    row_num,
                    student_id,
                    "ERR_DUPLICATE_STUDENT",
                    f"Duplicate StudentNo '{student_id}' in batch",
                    reject_log_path=reject_log_path,
                )
                result.rejected += 1
                continue

            # 4. Empty or invalid date
            if not date_str:
                log_reject(
                    result.rejects,
                    csv_file.name,
                    row_num,
                    student_id,
                    "ERR_EMPTY_DATE",
                    "LastPaymentDate is empty",
                    reject_log_path=reject_log_path,
                )
                result.rejected += 1
                continue

            try:
                datetime.strptime(date_str, "%Y-%m-%d")
            except ValueError:
                log_reject(
                    result.rejects,
                    csv_file.name,
                    row_num,
                    student_id,
                    "ERR_INVALID_DATE",
                    f"Invalid calendar date in LastPaymentDate: '{date_str}'",
                    reject_log_path=reject_log_path,
                )
                result.rejected += 1
                continue

            # 5. Formatted amount containing thousands separator (",")
            if "," in balance_str:
                log_reject(
                    result.rejects,
                    csv_file.name,
                    row_num,
                    student_id,
                    "ERR_FORMATTED_AMOUNT",
                    f"Formatted amount with comma in Balance: '{balance_str}'",
                    reject_log_path=reject_log_path,
                )
                result.rejected += 1
                continue

            # 6. Non-numeric or negative amount
            if not NUMERIC_RE.match(balance_str):
                log_reject(
                    result.rejects,
                    csv_file.name,
                    row_num,
                    student_id,
                    "ERR_NON_NUMERIC_AMOUNT",
                    f"Non-numeric or negative Balance: '{balance_str}'",
                    reject_log_path=reject_log_path,
                )
                result.rejected += 1
                continue

            balance = float(balance_str)

            # Compute status & reason
            if balance == 0.0:
                status = "CLEARED"
                reason = ""
                result.cleared += 1
            else:
                status = "HOLD"
                reason = f"Unpaid balance of PHP {balance:.2f}"
                result.hold += 1

            seen_students.add(student_id)
            upsert_clearance(conn, student_id, "Accounting", status, reason, "importer:accounting")
            result.accepted += 1

    conn.commit()
    _record_processed_manifest(manifest["signature"], Path(processed_log_path))
    return result


# ---------------------------------------------------------------------------
# Step 8: Smoke Test Runner
# ---------------------------------------------------------------------------
def _load_starter_students(json_path: Path) -> list[dict[str, Any]]:
    with json_path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    return payload["students"]


if __name__ == "__main__":
    root_dir = Path(__file__).resolve().parent
    students_data = _load_starter_students(root_dir / "starter_kit" / "registrar_students.json")
    valid_ids = {s["student_id"] for s in students_data}
    hmac_secret = os.getenv("MANIFEST_HMAC_KEY") or os.getenv("STARTER_HMAC_KEY") or ""

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        db_path = tmp / "smoke_test.db"
        processed_path = tmp / "processed_manifests.json"
        reject_log = tmp / "rejects.log"

        conn = sqlite3.connect(db_path)
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.executescript((root_dir / "schema.sql").read_text(encoding="utf-8"))

            # Seed students table so FK constraints on clearances succeed
            conn.executemany(
                """
                INSERT INTO students (student_id, name, program, year, email, registrar_status)
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
                    for s in students_data
                ],
            )
            conn.commit()

            # 1. Library XML import
            lib_xml = root_dir / "starter_kit" / "drop_folder" / "library_export_2026-11-20.xml"
            lib_res = import_library_xml(
                lib_xml,
                conn,
                valid_ids,
                hmac_key=hmac_secret,
                processed_log_path=processed_path,
                reject_log_path=reject_log,
            )
            print(
                f"[Library XML] accepted={lib_res.accepted} "
                f"(cleared={lib_res.cleared}, hold={lib_res.hold}), rejected={lib_res.rejected}"
            )
            for r in lib_res.rejects:
                print(
                    f"   REJECT row={r['row_index']} id={r['student_id_raw']} "
                    f"{r['error_code']}: {r['reason']}"
                )

            # 2. Accounting CSV import
            acc_csv = root_dir / "starter_kit" / "drop_folder" / "accounting_balances_2026-11-20.csv"
            acc_res = import_accounting_csv(
                acc_csv,
                conn,
                valid_ids,
                hmac_key=hmac_secret,
                processed_log_path=processed_path,
                reject_log_path=reject_log,
            )
            print(
                f"[Accounting CSV] accepted={acc_res.accepted} "
                f"(cleared={acc_res.cleared}, hold={acc_res.hold}), rejected={acc_res.rejected}"
            )
            for r in acc_res.rejects[:5]:
                print(
                    f"   REJECT row={r['row_index']} id={r['student_id_raw']} "
                    f"{r['error_code']}: {r['reason']}"
                )
            if len(acc_res.rejects) > 5:
                print(f"   ... ({len(acc_res.rejects) - 5} more accounting rejects)")

            # 3. Replay check
            try:
                import_library_xml(
                    lib_xml,
                    conn,
                    valid_ids,
                    hmac_key=hmac_secret,
                    processed_log_path=processed_path,
                    reject_log_path=reject_log,
                )
                raise AssertionError("Expected ManifestError on replay!")
            except ManifestError as exc:
                print(f"[Replay Check] PASS -> {exc}")

            # 4. Tamper test
            tampered_csv = root_dir / "starter_kit" / "tamper_tests" / "accounting_balances_2026-11-20.csv"
            try:
                import_accounting_csv(
                    tampered_csv,
                    conn,
                    valid_ids,
                    hmac_key=hmac_secret,
                    processed_log_path=processed_path,
                    reject_log_path=reject_log,
                )
                raise AssertionError("Expected ManifestError on tampered file!")
            except ManifestError as exc:
                print(f"[Tamper Test] PASS -> {exc}")
        finally:
            conn.close()
