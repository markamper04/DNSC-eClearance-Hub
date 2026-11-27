"""Unit and integration tests for importers.py and automate.py (R1, R2, R9, R11, R14)."""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import sqlite3
import uuid
from pathlib import Path
from typing import Callable

import pytest

from automate import run_automation
from importers import (
    ManifestError,
    import_accounting_csv,
    import_library_xml,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schema.sql"
STARTER_STUDENTS_PATH = REPO_ROOT / "starter_kit" / "registrar_students.json"
TAMPER_DIR = REPO_ROOT / "starter_kit" / "tamper_tests"

TEST_HMAC_KEY = "test-secret-key"
STARTER_DEMO_HMAC_KEY = "it312-starter-demo-key-change-me"


# ---------------------------------------------------------------------------
# Helpers for building synthetic XML / CSV payloads
# ---------------------------------------------------------------------------
def _make_library_xml(borrowers_xml: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<borrowers exported="2026-11-20" branch="DNSC Main Library">\n'
        f"{borrowers_xml}\n"
        "</borrowers>\n"
    )


def _borrower(
    card: str = "LIB-0001",
    name: str = "MORALES, Rhea B.",
    student_no: str = "2023-59928",
    program: str = "BSA",
    year_level: str = "4",
    email: str = "rhea.morales@dnsc.edu.ph",
    last_borrowed: str = "10/27/2026",
    unreturned_books: str = "0",
    unpaid_fines: str = "0.00",
) -> str:
    return (
        f'  <borrower card="{card}">\n'
        f"    <name>{name}</name>\n"
        f"    <studentNo>{student_no}</studentNo>\n"
        f"    <program>{program}</program>\n"
        f"    <yearLevel>{year_level}</yearLevel>\n"
        f"    <email>{email}</email>\n"
        f"    <lastBorrowed>{last_borrowed}</lastBorrowed>\n"
        f"    <unreturnedBooks>{unreturned_books}</unreturnedBooks>\n"
        f"    <unpaidFines>{unpaid_fines}</unpaidFines>\n"
        "  </borrower>"
    )


def _make_accounting_csv(rows: list[str]) -> str:
    header = "StudentNo,Name,Term,Assessed,Paid,Balance,LastPaymentDate"
    return "\n".join([header, *rows]) + "\n"


# ---------------------------------------------------------------------------
# Step 1: Reusable Pytest Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def starter_students() -> list[dict]:
    payload = json.loads(STARTER_STUDENTS_PATH.read_text(encoding="utf-8"))
    return payload["students"]


@pytest.fixture
def valid_student_ids(starter_students: list[dict]) -> set[str]:
    return {s["student_id"] for s in starter_students}


@pytest.fixture
def db_conn(starter_students: list[dict]):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
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
            for s in starter_students
        ],
    )
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture
def sign_file() -> Callable[..., Path]:
    """Write a signed .manifest.json next to any temporary XML/CSV file."""

    def _sign(file_path: Path, secret_key: str = TEST_HMAC_KEY, source: str = "test") -> Path:
        raw_bytes = file_path.read_bytes()
        manifest = {
            "file": file_path.name,
            "source": source,
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "record_count": 1,
            "created_at": "2026-11-27T19:00:00+08:00",
            "nonce": uuid.uuid4().hex,
        }
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        manifest["signature"] = hmac.new(
            secret_key.encode("utf-8"), canonical, hashlib.sha256
        ).hexdigest()

        manifest_path = Path(f"{file_path}.manifest.json")
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest_path

    return _sign


# ---------------------------------------------------------------------------
# Step 2: Valid Mapping Tests (3 Test Cases)
# ---------------------------------------------------------------------------
def test_library_xml_maps_cleared_and_hold(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    xml_file = tmp_path / "library_valid.xml"
    xml_file.write_text(
        _make_library_xml(
            "\n".join(
                [
                    _borrower(
                        card="LIB-0001",
                        student_no="2023-59928",
                        name="MORALES, Rhea B.",
                        program="BSA",
                        unreturned_books="0",
                        unpaid_fines="0.00",
                    ),
                    _borrower(
                        card="LIB-0002",
                        student_no="2025-81367",
                        name="MORALES, Ana C.",
                        program="BSED-MATH",
                        unreturned_books="2",
                        unpaid_fines="40.50",
                    ),
                ]
            )
        ),
        encoding="utf-8",
    )
    sign_file(xml_file, source="library")

    res = import_library_xml(
        xml_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=tmp_path / "processed.json",
        reject_log_path=tmp_path / "rejects.log",
    )

    assert res.accepted == 2
    assert res.cleared == 1
    assert res.hold == 1
    assert res.rejected == 0

    rows = {
        r["student_id"]: dict(r)
        for r in db_conn.execute(
            "SELECT * FROM clearances WHERE office = 'Library'"
        ).fetchall()
    }
    assert set(rows.keys()) == {"2023-59928", "2025-81367"}
    assert rows["2023-59928"]["status"] == "CLEARED"
    assert rows["2023-59928"]["reason"] == ""
    assert rows["2025-81367"]["status"] == "HOLD"
    assert "2 unreturned book(s)" in rows["2025-81367"]["reason"]
    assert "40.50" in rows["2025-81367"]["reason"]


def test_accounting_csv_maps_cleared_and_hold(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    csv_file = tmp_path / "accounting_valid.csv"
    csv_file.write_text(
        _make_accounting_csv(
            [
                '2026-29417,"Navarro, Mark",1S 2026-2027,9200.00,9200.00,0.00,2026-09-11',
                '2024-46072,"Santos, Rhea",1S 2026-2027,9200.00,8450.00,750.00,2026-10-27',
            ]
        ),
        encoding="utf-8",
    )
    sign_file(csv_file, source="accounting")

    res = import_accounting_csv(
        csv_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=tmp_path / "processed.json",
        reject_log_path=tmp_path / "rejects.log",
    )

    assert res.accepted == 2
    assert res.cleared == 1
    assert res.hold == 1
    assert res.rejected == 0

    rows = {
        r["student_id"]: dict(r)
        for r in db_conn.execute(
            "SELECT * FROM clearances WHERE office = 'Accounting'"
        ).fetchall()
    }
    assert set(rows.keys()) == {"2026-29417", "2024-46072"}
    assert rows["2026-29417"]["status"] == "CLEARED"
    assert rows["2026-29417"]["reason"] == ""
    assert rows["2024-46072"]["status"] == "HOLD"
    assert "750.00" in rows["2024-46072"]["reason"]


def test_importer_upsert_updates_existing_clearance(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    processed_log = tmp_path / "processed.json"
    reject_log = tmp_path / "rejects.log"

    # First import: HOLD
    csv_hold = tmp_path / "accounting_day1.csv"
    csv_hold.write_text(
        _make_accounting_csv(
            ['2024-46072,"Santos, Rhea",1S 2026-2027,9200.00,8700.00,500.00,2026-10-20']
        ),
        encoding="utf-8",
    )
    sign_file(csv_hold, source="accounting")
    import_accounting_csv(
        csv_hold,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=processed_log,
        reject_log_path=reject_log,
    )

    # Second import (newer signed file): CLEARED
    csv_cleared = tmp_path / "accounting_day2.csv"
    csv_cleared.write_text(
        _make_accounting_csv(
            ['2024-46072,"Santos, Rhea",1S 2026-2027,9200.00,9200.00,0.00,2026-10-27']
        ),
        encoding="utf-8",
    )
    sign_file(csv_cleared, source="accounting")
    import_accounting_csv(
        csv_cleared,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=processed_log,
        reject_log_path=reject_log,
    )

    rows = db_conn.execute(
        "SELECT * FROM clearances WHERE student_id = ? AND office = 'Accounting'",
        ("2024-46072",),
    ).fetchall()
    assert len(rows) == 1
    assert rows[0]["status"] == "CLEARED"
    assert rows[0]["reason"] == ""


# ---------------------------------------------------------------------------
# Step 3: Dirty-Data Reject Tests — Library XML (7 Test Cases)
# ---------------------------------------------------------------------------
def test_library_rejects_bad_student_id(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    xml_file = tmp_path / "lib_bad_id.xml"
    xml_file.write_text(
        _make_library_xml(_borrower(card="LIB-0027", student_no="2026-1234")),
        encoding="utf-8",
    )
    sign_file(xml_file, source="library")

    res = import_library_xml(
        xml_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=tmp_path / "processed.json",
        reject_log_path=tmp_path / "rejects.log",
    )
    assert res.accepted == 0
    assert res.rejected == 1
    assert res.rejects[0]["error_code"] == "ERR_BAD_ID"
    assert db_conn.execute("SELECT COUNT(*) FROM clearances").fetchone()[0] == 0


def test_library_rejects_unknown_student(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    xml_file = tmp_path / "lib_unknown.xml"
    xml_file.write_text(
        _make_library_xml(_borrower(card="LIB-0026", student_no="2025-77777")),
        encoding="utf-8",
    )
    sign_file(xml_file, source="library")

    res = import_library_xml(
        xml_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=tmp_path / "processed.json",
        reject_log_path=tmp_path / "rejects.log",
    )
    assert res.accepted == 0
    assert res.rejected == 1
    assert res.rejects[0]["error_code"] == "ERR_UNKNOWN_STUDENT"
    assert db_conn.execute("SELECT COUNT(*) FROM clearances").fetchone()[0] == 0


def test_library_rejects_bad_name_format(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    xml_file = tmp_path / "lib_bad_name.xml"
    xml_file.write_text(
        _make_library_xml(_borrower(card="LIB-0026", student_no="2023-59928", name="PASCUAL Ramil")),
        encoding="utf-8",
    )
    sign_file(xml_file, source="library")

    res = import_library_xml(
        xml_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=tmp_path / "processed.json",
        reject_log_path=tmp_path / "rejects.log",
    )
    assert res.accepted == 0
    assert res.rejected == 1
    assert res.rejects[0]["error_code"] == "ERR_BAD_NAME"


def test_library_rejects_unknown_program_bshm(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    xml_file = tmp_path / "lib_bshm.xml"
    xml_file.write_text(
        _make_library_xml(_borrower(card="LIB-0028", student_no="2023-59928", program="BSHM")),
        encoding="utf-8",
    )
    sign_file(xml_file, source="library")

    res = import_library_xml(
        xml_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=tmp_path / "processed.json",
        reject_log_path=tmp_path / "rejects.log",
    )
    assert res.accepted == 0
    assert res.rejected == 1
    assert res.rejects[0]["error_code"] == "ERR_INVALID_PROGRAM"


def test_library_rejects_impossible_date_31_09_2026(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    xml_file = tmp_path / "lib_bad_date.xml"
    xml_file.write_text(
        _make_library_xml(
            _borrower(card="LIB-0028", student_no="2023-59928", last_borrowed="31/09/2026")
        ),
        encoding="utf-8",
    )
    sign_file(xml_file, source="library")

    res = import_library_xml(
        xml_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=tmp_path / "processed.json",
        reject_log_path=tmp_path / "rejects.log",
    )
    assert res.accepted == 0
    assert res.rejected == 1
    assert res.rejects[0]["error_code"] == "ERR_INVALID_DATE"


def test_library_rejects_negative_fine(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    xml_file = tmp_path / "lib_neg_fine.xml"
    xml_file.write_text(
        _make_library_xml(
            _borrower(card="LIB-0029", student_no="2023-59928", unpaid_fines="-50.00")
        ),
        encoding="utf-8",
    )
    sign_file(xml_file, source="library")

    res = import_library_xml(
        xml_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=tmp_path / "processed.json",
        reject_log_path=tmp_path / "rejects.log",
    )
    assert res.accepted == 0
    assert res.rejected == 1
    assert res.rejects[0]["error_code"] == "ERR_NEGATIVE_FINE"


def test_library_rejects_duplicate_card(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    xml_file = tmp_path / "lib_dup_card.xml"
    xml_file.write_text(
        _make_library_xml(
            "\n".join(
                [
                    _borrower(card="LIB-0001", student_no="2023-59928", name="MORALES, Rhea B."),
                    _borrower(card="LIB-0001", student_no="2025-81367", name="MORALES, Ana C."),
                ]
            )
        ),
        encoding="utf-8",
    )
    sign_file(xml_file, source="library")

    res = import_library_xml(
        xml_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=tmp_path / "processed.json",
        reject_log_path=tmp_path / "rejects.log",
    )
    assert res.accepted == 1
    assert res.rejected == 1
    assert res.rejects[0]["error_code"] == "ERR_DUPLICATE_CARD"


# ---------------------------------------------------------------------------
# Step 3: Dirty-Data Reject Tests — Accounting CSV (4 Test Cases)
# ---------------------------------------------------------------------------
def test_accounting_rejects_formatted_amount_with_comma(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    csv_file = tmp_path / "acc_comma.csv"
    csv_file.write_text(
        _make_accounting_csv(
            ['2025-93355,"Flores, Nicole",1S 2026-2027,"10,450.50",0.00,"10,450.50",2026-10-15']
        ),
        encoding="utf-8",
    )
    sign_file(csv_file, source="accounting")

    res = import_accounting_csv(
        csv_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=tmp_path / "processed.json",
        reject_log_path=tmp_path / "rejects.log",
    )
    assert res.accepted == 0
    assert res.rejected == 1
    assert res.rejects[0]["error_code"] == "ERR_FORMATTED_AMOUNT"


def test_accounting_rejects_empty_date(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    csv_file = tmp_path / "acc_empty_date.csv"
    csv_file.write_text(
        _make_accounting_csv(
            ['2025-93355,"Flores, Nicole",1S 2026-2027,9200.00,9200.00,0.00,']
        ),
        encoding="utf-8",
    )
    sign_file(csv_file, source="accounting")

    res = import_accounting_csv(
        csv_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=tmp_path / "processed.json",
        reject_log_path=tmp_path / "rejects.log",
    )
    assert res.accepted == 0
    assert res.rejected == 1
    assert res.rejects[0]["error_code"] == "ERR_EMPTY_DATE"


def test_accounting_rejects_non_numeric_amount(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    csv_file = tmp_path / "acc_non_numeric.csv"
    csv_file.write_text(
        _make_accounting_csv(
            ['2024-45481,"Dela Cruz, Mark",1S 2026-2027,9200.00,0.00,N/A,2026-10-15']
        ),
        encoding="utf-8",
    )
    sign_file(csv_file, source="accounting")

    res = import_accounting_csv(
        csv_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=tmp_path / "processed.json",
        reject_log_path=tmp_path / "rejects.log",
    )
    assert res.accepted == 0
    assert res.rejected == 1
    assert res.rejects[0]["error_code"] == "ERR_NON_NUMERIC_AMOUNT"


def test_accounting_rejects_unknown_student(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    csv_file = tmp_path / "acc_unknown.csv"
    csv_file.write_text(
        _make_accounting_csv(
            ['2023-55555,"Ghost, Student",1S 2026-2027,9200.00,9200.00,0.00,2026-10-15']
        ),
        encoding="utf-8",
    )
    sign_file(csv_file, source="accounting")

    res = import_accounting_csv(
        csv_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=tmp_path / "processed.json",
        reject_log_path=tmp_path / "rejects.log",
    )
    assert res.accepted == 0
    assert res.rejected == 1
    assert res.rejects[0]["error_code"] == "ERR_UNKNOWN_STUDENT"


# ---------------------------------------------------------------------------
# Step 4: Security & Tamper Tests (3 Test Cases — R14)
# ---------------------------------------------------------------------------
def test_rejects_starter_kit_tamper_tests(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
):
    tampered_csv = TAMPER_DIR / "accounting_balances_2026-11-20.csv"
    with pytest.raises(ManifestError, match="(?i)tampered|hash|signature"):
        import_accounting_csv(
            tampered_csv,
            db_conn,
            valid_student_ids,
            hmac_key=STARTER_DEMO_HMAC_KEY,
            processed_log_path=tmp_path / "processed.json",
            reject_log_path=tmp_path / "rejects.log",
        )
    assert db_conn.execute("SELECT COUNT(*) FROM clearances").fetchone()[0] == 0


def test_rejects_missing_manifest(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
):
    xml_file = tmp_path / "no_manifest.xml"
    xml_file.write_text(_make_library_xml(_borrower()), encoding="utf-8")

    with pytest.raises(ManifestError, match="(?i)missing manifest"):
        import_library_xml(
            xml_file,
            db_conn,
            valid_student_ids,
            hmac_key=TEST_HMAC_KEY,
            processed_log_path=tmp_path / "processed.json",
            reject_log_path=tmp_path / "rejects.log",
        )
    assert db_conn.execute("SELECT COUNT(*) FROM clearances").fetchone()[0] == 0


def test_rejects_replayed_file(
    tmp_path: Path,
    db_conn: sqlite3.Connection,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
):
    xml_file = tmp_path / "replay_test.xml"
    xml_file.write_text(_make_library_xml(_borrower()), encoding="utf-8")
    sign_file(xml_file, source="library")

    processed_log = tmp_path / "processed.json"
    reject_log = tmp_path / "rejects.log"

    first = import_library_xml(
        xml_file,
        db_conn,
        valid_student_ids,
        hmac_key=TEST_HMAC_KEY,
        processed_log_path=processed_log,
        reject_log_path=reject_log,
    )
    assert first.accepted == 1

    with pytest.raises(ManifestError, match="(?i)replay detected"):
        import_library_xml(
            xml_file,
            db_conn,
            valid_student_ids,
            hmac_key=TEST_HMAC_KEY,
            processed_log_path=processed_log,
            reject_log_path=reject_log,
        )


# ---------------------------------------------------------------------------
# Step 5: automate.py End-to-End Tests (2 Test Cases)
# ---------------------------------------------------------------------------
def test_automate_archives_valid_files_and_writes_timestamped_log(
    tmp_path: Path,
    valid_student_ids: set[str],
    sign_file: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("MANIFEST_HMAC_KEY", TEST_HMAC_KEY)

    drop_dir = tmp_path / "drop_folder"
    archive_dir = tmp_path / "archive"
    quarantine_dir = tmp_path / "quarantine"
    logs_dir = tmp_path / "logs"
    db_path = tmp_path / "test_eclearance.db"
    drop_dir.mkdir()

    # Drop valid signed XML (1 CLEARED, 1 HOLD) + valid signed CSV (1 CLEARED, 1 HOLD)
    xml_file = drop_dir / "library_export.xml"
    xml_file.write_text(
        _make_library_xml(
            "\n".join(
                [
                    _borrower(card="LIB-0001", student_no="2023-59928", unreturned_books="0", unpaid_fines="0.00"),
                    _borrower(card="LIB-0002", student_no="2025-81367", name="MORALES, Ana C.", program="BSED-MATH", unreturned_books="1", unpaid_fines="25.00"),
                ]
            )
        ),
        encoding="utf-8",
    )
    sign_file(xml_file, secret_key=TEST_HMAC_KEY, source="library")

    csv_file = drop_dir / "accounting_balances.csv"
    csv_file.write_text(
        _make_accounting_csv(
            [
                '2026-29417,"Navarro, Mark",1S 2026-2027,9200.00,9200.00,0.00,2026-09-11',
                '2024-46072,"Santos, Rhea",1S 2026-2027,9200.00,8500.00,700.00,2026-10-27',
            ]
        ),
        encoding="utf-8",
    )
    sign_file(csv_file, secret_key=TEST_HMAC_KEY, source="accounting")

    summary = run_automation(
        drop_dir=drop_dir,
        archive_dir=archive_dir,
        quarantine_dir=quarantine_dir,
        logs_dir=logs_dir,
        db_path=db_path,
        valid_student_ids=None,  # Exercises auto-seeding from starter_kit JSON
    )

    # drop_folder/ is now empty
    assert list(drop_dir.iterdir()) == []

    # Both data files + their .manifest.json files exist in archive/
    archived_names = [p.name for p in archive_dir.rglob("*") if p.is_file()]
    assert any(n.endswith("library_export.xml") for n in archived_names)
    assert any(n.endswith("library_export.xml.manifest.json") for n in archived_names)
    assert any(n.endswith("accounting_balances.csv") for n in archived_names)
    assert any(n.endswith("accounting_balances.csv.manifest.json") for n in archived_names)

    # Timestamped import_*.log exists
    import_logs = list(logs_dir.glob("import_*.log"))
    assert len(import_logs) == 1

    # Daily hold_summary_*.txt exists and lists both HOLD students grouped by office
    hold_reports = list(logs_dir.glob("hold_summary_*.txt"))
    assert len(hold_reports) == 1
    report_text = hold_reports[0].read_text(encoding="utf-8")
    assert "[Library]" in report_text
    assert "2025-81367" in report_text
    assert "[Accounting]" in report_text
    assert "2024-46072" in report_text
    assert summary["hold_counts"] == {"Accounting": 1, "Library": 1}


def test_automate_quarantines_tampered_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("MANIFEST_HMAC_KEY", STARTER_DEMO_HMAC_KEY)

    drop_dir = tmp_path / "drop_folder"
    archive_dir = tmp_path / "archive"
    quarantine_dir = tmp_path / "quarantine"
    logs_dir = tmp_path / "logs"
    db_path = tmp_path / "test_tamper.db"
    drop_dir.mkdir()

    shutil.copy2(
        TAMPER_DIR / "accounting_balances_2026-11-20.csv",
        drop_dir / "accounting_balances_2026-11-20.csv",
    )
    shutil.copy2(
        TAMPER_DIR / "accounting_balances_2026-11-20.csv.manifest.json",
        drop_dir / "accounting_balances_2026-11-20.csv.manifest.json",
    )

    summary = run_automation(
        drop_dir=drop_dir,
        archive_dir=archive_dir,
        quarantine_dir=quarantine_dir,
        logs_dir=logs_dir,
        db_path=db_path,
    )

    # Tampered file is moved to quarantine/ and NOT archive/
    assert list(drop_dir.iterdir()) == []
    assert [p for p in archive_dir.rglob("*") if p.is_file()] == []
    quarantined_names = [p.name for p in quarantine_dir.rglob("*") if p.is_file()]
    assert any(n.endswith("accounting_balances_2026-11-20.csv") for n in quarantined_names)
    assert any(n.endswith("accounting_balances_2026-11-20.csv.manifest.json") for n in quarantined_names)
    assert summary["quarantined"] == ["accounting_balances_2026-11-20.csv"]

    # logs/import_*.log contains a security alert
    import_logs = list(logs_dir.glob("import_*.log"))
    assert len(import_logs) == 1
    log_text = import_logs[0].read_text(encoding="utf-8")
    assert "SECURITY ALERT" in log_text
