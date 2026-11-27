# DNSC e-Clearance Hub — Data Mapping & Validation Specification

This document defines the end-to-end data mapping, security verification, validation, and rejection rules for importing external office exports (**Library XML** and **Accounting CSV**) into the DNSC e-Clearance Hub SQLite database (`schema.sql`), satisfying **R9**, **R14**, and **Appendix F**.

---

## 1. Overview & Target Schema

Both external data sources are validated against the Registrar masterlist (`starter_kit/registrar_students.json`, 40 synthetic students) and transformed into rows in the `clearances` table defined in `schema.sql`.

### Target Table: `clearances`

```sql
CREATE TABLE IF NOT EXISTS clearances (
    student_id TEXT NOT NULL,
    office TEXT NOT NULL CHECK (office IN ('Registrar', 'Library', 'Accounting', 'Student Affairs')),
    status TEXT NOT NULL CHECK (status IN ('CLEARED', 'HOLD')),
    reason TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (student_id, office),
    FOREIGN KEY (student_id) REFERENCES students(student_id)
);
```

| Column | Type & Constraints | Mapping Description |
|---|---|---|
| `student_id` | `TEXT NOT NULL`, PK (composite), FK → `students.student_id` | Must match `^\d{4}-\d{5}$` and exist in `valid_student_ids` loaded from the Registrar masterlist (`starter_kit/registrar_students.json`). |
| `office` | `TEXT NOT NULL`, PK (composite), `CHECK (office IN ('Registrar', 'Library', 'Accounting', 'Student Affairs'))` | Hardcoded to `'Library'` for Library XML imports and `'Accounting'` for Accounting CSV imports. |
| `status` | `TEXT NOT NULL`, `CHECK (status IN ('CLEARED', 'HOLD'))` | Computed from office-specific obligation fields: `'CLEARED'` when all obligations are zero; `'HOLD'` otherwise. |
| `reason` | `TEXT NOT NULL DEFAULT ''` | Empty string `''` when `status == 'CLEARED'`; human-readable explanation when `status == 'HOLD'` (e.g., `"1 unreturned book(s); unpaid fine of PHP 40.50"` or `"Unpaid balance of PHP 1,500.00"`). |
| `updated_by` | `TEXT NOT NULL` | System importer identifier: `'importer:library'` for XML imports and `'importer:accounting'` for CSV imports. |
| `updated_at` | `TEXT NOT NULL` | ISO-8601 timestamp generated at import time (e.g., `2026-11-27T19:30:00+08:00` or UTC `2026-11-27T11:30:00Z`). |

### Registrar Masterlist Reference (`starter_kit/registrar_students.json`)

- **Student ID Format**: `YYYY-NNNNN` — regex `^\d{4}-\d{5}$` (e.g., `2026-29417`, `2023-59928`).
- **Masterlist Name Format**: Stored as separate fields: `last_name`, `first_name`, and `middle_initial` (e.g., `last_name: "Dela Cruz"`, `first_name: "Mark"`, `middle_initial: "C"`; supports multi-word names such as `first_name: "John Lloyd"`).
- **Valid Program Codes (Registrar Allow-List)**:
  - `AGRI` — Bachelor of Science in Agriculture (Library XML alias: `BSA`)
  - `CRIM` — Bachelor of Science in Criminology (Library XML alias: `BSCRIM`)
  - `EDMATH` — Bachelor of Secondary Education major in Mathematics (Library XML alias: `BSED-MATH`)
  - `IS` — Bachelor of Science in Information Systems (Library XML alias: `BSIS`)
  - `IT` — Bachelor of Science in Information Technology (Library XML alias: `BSIT`)
  - *Note*: `BSHM` is **not** in the Registrar program allow-list and must be rejected.
- **Registrar Enrollment Status (`LOA` handling)**: 39 of 40 students have `status: "ENROLLED"` and 1 student (`2025-81367`, Ana C. Morales) has `status: "LOA"` (Leave of Absence). LOA students remain valid members of `valid_student_ids` so their Library and Accounting clearance obligations are still tracked, while their `students.registrar_status` column preserves `'LOA'`.

---

## 2. Pre-Import Security Gate (R14)

No XML or CSV file in `drop_folder/` is opened for row-level parsing until **all** of the following security checks pass:

- **Manifest Presence**: A matching sidecar manifest file (`<filename>.manifest.json`) must exist alongside the export file in `drop_folder/` (e.g., `library_export_2026-11-20.xml.manifest.json`, `accounting_balances_2026-11-20.csv.manifest.json`).
- **HMAC-SHA256 Signature & File Hash Verification**:
  1. Canonicalize the manifest JSON (all keys except `"signature"`, sorted keys, compact separators `(",", ":")`) and compute its HMAC-SHA256 digest using the secret key loaded from `.env` (never hardcoded). Compare it against `manifest["signature"]` using constant-time comparison (`hmac.compare_digest`).
  2. Compute the SHA-256 digest of the raw export file bytes and compare it against `manifest["sha256"]` using `hmac.compare_digest`.
- **Replay Protection**: Verify that the file has not already been imported by checking `manifest["signature"]` against previously recorded imports in `logs/processed_manifests.json`.
- **Fail-Closed Rejection**: If any check fails (for example, `starter_kit/tamper_tests/accounting_balances_2026-11-20.csv`, where a balance was modified after signing), the **entire file** is immediately rejected before row-level parsing begins, zero rows are written to `clearances`, and a security event is recorded in the reject log and `audit_log`.

---

## 3. Source 1: Library XML Mapping Table

- **Source File**: `starter_kit/drop_folder/library_export_2026-11-20.xml` (29 `<borrower>` records)
- **Root Element**: `<borrowers exported="2026-11-20" branch="DNSC Main Library">`
- **Record Element**: `<borrower card="LIB-0001">`

| Source Field | Target Field | Transformation / Rule | Reject Condition |
|---|---|---|---|
| `@card` (attribute on `<borrower>`) | *(validation / audit only — not stored in `clearances`)* | Strip whitespace; validate format `^LIB-\d{4}$`; track seen `@card` values and seen `studentNo` values within the same XML batch. | Missing `@card`, malformed card ID, or duplicate `@card` / duplicate borrower card for a `studentNo` already seen in the same XML batch (e.g., `LIB-0029` duplicates `2023-59928` from `LIB-0001`) → `ERR_DUPLICATE_CARD`. |
| `<studentNo>` | `clearances.student_id` | Strip whitespace; validate against allow-list regex `^\d{4}-\d{5}$`; confirm existence in Registrar `valid_student_ids`. | Does not match `^\d{4}-\d{5}$` (e.g., `2026-1234` in `LIB-0027`) → `ERR_BAD_ID`; or not found in `valid_student_ids` (e.g., `2025-77777` in `LIB-0026`, `2024-99999` in `LIB-0028`) → `ERR_UNKNOWN_STUDENT`. |
| `<name>` | *(validation only — canonical name comes from `students`)* | Strip whitespace; validate strict `"LAST, First M."` format matching `^[A-Z][A-Z\s'-]+,\s[A-Za-z][A-Za-z\s'-]+\s[A-Z]\.$`. | Does not match required `"LAST, First M."` format (e.g., missing comma/middle initial in `PASCUAL Ramil` on `LIB-0026`, or contains digits/invalid characters) → `ERR_BAD_NAME`. |
| `<program>` | *(validation only — canonical program comes from `students`)* | Strip whitespace and uppercase; map Library alias to Registrar `program_code` allow-list (`BSA→AGRI`, `BSCRIM→CRIM`, `BSED-MATH→EDMATH`, `BSIS→IS`, `BSIT→IT`). | Not in the Registrar/Library program allow-list (e.g., `BSHM` in `LIB-0028`) → `ERR_INVALID_PROGRAM`. |
| `<yearLevel>` | *(validation only)* | Strip whitespace; parse as integer and verify range `1 <= yearLevel <= 4`. | Non-integer or outside `1..4` → `ERR_INVALID_YEAR`. |
| `<email>` | *(validation only)* | Strip whitespace and lowercase; validate basic email format `^[^@\s]+@dnsc\.edu\.ph$`. | Empty or invalid email format → `ERR_INVALID_EMAIL`. |
| `<lastBorrowed>` | *(validation only)* | Strip whitespace; parse strictly with `datetime.strptime(val, "%m/%d/%Y")` to confirm a real calendar date, normalizing internally to ISO-8601 `YYYY-MM-DD`. | Empty, wrong format, or not a real calendar date under `strptime` (e.g., `31/09/2026` in `LIB-0028` — September has only 30 days) → `ERR_INVALID_DATE`. |
| `<unreturnedBooks>` | *(input to computed `status` & `reason`)* | Strip whitespace; parse as non-negative integer (`int >= 0`). | Empty, non-integer, or `< 0` → `ERR_NON_NUMERIC_AMOUNT` / `ERR_NEGATIVE_AMOUNT`. |
| `<unpaidFines>` | *(input to computed `status` & `reason`)* | Strip whitespace; parse as non-negative decimal (`Decimal >= 0.00`, quantized to 2 decimal places). | Non-numeric, empty, or `< 0` (e.g., `-5.00` in `LIB-0029`) → `ERR_NEGATIVE_FINE` (if `< 0`) or `ERR_NON_NUMERIC_AMOUNT` (if non-numeric). |
| *(constant)* | `clearances.office`, `updated_by`, `updated_at` | Set `office = 'Library'`, `updated_by = 'importer:library'`, `updated_at = <ISO-8601 import timestamp>`. | N/A (system-generated). |
| **Computed `status` & `reason`** | `clearances.status`, `clearances.reason` | If `unreturnedBooks == 0` **AND** `unpaidFines == 0.00` → `status = 'CLEARED'`, `reason = ''`. Otherwise → `status = 'HOLD'` with `reason` joining active obligations: `"<N> unreturned book(s)"` (if `> 0`) and/or `"unpaid fine of PHP <amount>"` (if `> 0.00`), separated by `"; "`. | Any field-level validation failure above rejects the entire `<borrower>` row before upsert. |

### Dirty Rows Identified in `library_export_2026-11-20.xml`

- **Row 26 (`LIB-0026`)**: `<name>PASCUAL Ramil</name>` (`ERR_BAD_NAME`) and `<studentNo>2025-77777</studentNo>` (`ERR_UNKNOWN_STUDENT`).
- **Row 27 (`LIB-0027`)**: `<studentNo>2026-1234</studentNo>` (`ERR_BAD_ID` — only 4 digits after hyphen).
- **Row 28 (`LIB-0028`)**: `<studentNo>2024-99999</studentNo>` (`ERR_UNKNOWN_STUDENT`), `<program>BSHM</program>` (`ERR_INVALID_PROGRAM`), and `<lastBorrowed>31/09/2026</lastBorrowed>` (`ERR_INVALID_DATE`).
- **Row 29 (`LIB-0029`)**: Duplicate borrower card for `2023-59928` already seen in `LIB-0001` (`ERR_DUPLICATE_CARD`) and `<unpaidFines>-5.00</unpaidFines>` (`ERR_NEGATIVE_FINE`).

---

## 4. Source 2: Accounting CSV Mapping Table

- **Source File**: `starter_kit/drop_folder/accounting_balances_2026-11-20.csv` (42 data rows, lines 2–43)
- **Exact CSV Header (Line 1)**: `StudentNo,Name,Term,Assessed,Paid,Balance,LastPaymentDate`

| Source Field | Target Field | Transformation / Rule | Reject Condition |
|---|---|---|---|
| **Row Structure** *(CSV line)* | *(structural validation)* | Parse with Python `csv.reader` (respecting quoted fields); verify exact column count `len(row) == 7`. | Missing or extra columns (`len(row) != 7`, corrupted CSV row) → `ERR_CORRUPTED_ROW`. |
| `StudentNo` | `clearances.student_id` | Strip whitespace; validate against allow-list regex `^\d{4}-\d{5}$`; confirm existence in Registrar `valid_student_ids`; track seen `StudentNo` per CSV batch. | Does not match `^\d{4}-\d{5}$` → `ERR_BAD_ID`; not found in `valid_student_ids` (e.g., `2023-55555` on line 42) → `ERR_UNKNOWN_STUDENT`; duplicate `StudentNo` in same batch (e.g., `2024-45481` on line 43) → `ERR_DUPLICATE_STUDENT`. |
| `Name` | *(validation only — canonical name comes from `students`)* | Strip whitespace; validate `"Last, First"` format matching `^[A-Za-z][A-Za-z\s'-]+,\s[A-Za-z][A-Za-z\s'-]+$`. | Missing comma or invalid name format (e.g., `dup row` on line 43) → `ERR_BAD_NAME`. |
| `Term` | *(validation only)* | Strip whitespace; validate academic term format (e.g., `^(1S|2S|SUM)\s\d{4}-\d{4}$`, such as `1S 2026-2027`). | Empty or malformed term string → `ERR_INVALID_TERM`. |
| `Assessed` | *(validation only)* | Strip whitespace; informational total assessment amount. | *(Informational / pass-through in current importer; `Balance` is the clearance-driving field validated strictly.)* |
| `Paid` | *(validation only)* | Strip whitespace; informational amount paid. | *(Informational / pass-through in current importer; `Balance` is the clearance-driving field validated strictly.)* |
| `Balance` | *(input to computed `status` & `reason`)* | Strip whitespace; must be a valid non-negative decimal (`Decimal >= 0.00`, quantized to 2 decimal places). | Contains thousands separator/commas (e.g., `"10,450.50"` on line 8) → `ERR_FORMATTED_AMOUNT`; non-numeric text (e.g., `x` on line 43, `"N/A"`) or empty → `ERR_NON_NUMERIC_AMOUNT`; or `< 0` → `ERR_NEGATIVE_AMOUNT`. |
| `LastPaymentDate` | *(validation only)* | Strip whitespace; parse strictly with `datetime.strptime(val, "%Y-%m-%d")` to confirm a real calendar date. | Empty/blank date (e.g., lines 8, 18, 22, 23, 27, 29, 35, 37, 42) → `ERR_EMPTY_DATE`; or invalid calendar date (e.g., `2026-13-01` on line 43) → `ERR_INVALID_DATE`. |
| *(constant)* | `clearances.office`, `updated_by`, `updated_at` | Set `office = 'Accounting'`, `updated_by = 'importer:accounting'`, `updated_at = <ISO-8601 import timestamp>`. | N/A (system-generated). |
| **Computed `status` & `reason`** | `clearances.status`, `clearances.reason` | If `Balance == 0.00` → `status = 'CLEARED'`, `reason = ''`. Otherwise (`Balance > 0.00`) → `status = 'HOLD'`, `reason = "Unpaid balance of PHP <amount>"` (formatted with 2 decimal places, e.g., `"Unpaid balance of PHP 1,500.00"`). | Any field-level or row-structure failure above rejects the CSV row before upsert. |

> **Note on Starter Kit CSV Formatting**: In `starter_kit/drop_folder/accounting_balances_2026-11-20.csv`, valid student rows (lines 2–41) include quoted comma-formatted amounts (e.g., `"9,200.00"`, `"10,450.50"`) and blank `LastPaymentDate` values when `Paid == 0.00`. Under **strict mode**, those trigger `ERR_FORMATTED_AMOUNT` and `ERR_EMPTY_DATE` as listed above; if the importer is configured in **normalize mode**, commas in valid numeric strings (`^\d{1,3}(,\d{3})+(\.\d{2})?$`) are stripped before `Decimal` conversion and blank `LastPaymentDate` is permitted solely when `Paid == 0.00`.

### Dirty Rows Identified in `accounting_balances_2026-11-20.csv`

- **Lines 8, 18, 22, 23, 27, 29, 35, 37** (e.g., `2025-93355,"Flores, Nicole",...,"10,450.50",0.00,"10,450.50",`): Formatted amounts with thousands separators (`"10,450.50"`) and empty `LastPaymentDate`.
- **Line 42**: `2023-55555,"Ghost, Student",1S 2026-2027,"9,200.00",0.00,"9,200.00",` — `ERR_UNKNOWN_STUDENT` (plus formatted amount & empty date).
- **Line 43**: `2024-45481,dup row,1S 2026-2027,"9,200.00",abc,x,2026-13-01` — `ERR_DUPLICATE_STUDENT`, `ERR_BAD_NAME`, `ERR_NON_NUMERIC_AMOUNT` (`abc`, `x`), and `ERR_INVALID_DATE` (`2026-13-01`).

---

## 5. Reject Rules Catalog & Reject Log Format

### Reject Error Code Catalog

| Error Code | Scope | Applies To | Description |
|---|---|---|---|
| `ERR_MISSING_MANIFEST` | File (R14) | XML, CSV | Required `<filename>.manifest.json` file is missing from `drop_folder/`. |
| `ERR_TAMPERED_MANIFEST` | File (R14) | XML, CSV | Manifest HMAC-SHA256 signature failed `hmac.compare_digest` verification. |
| `ERR_HASH_MISMATCH` | File (R14) | XML, CSV | Raw file SHA-256 digest does not match `manifest["sha256"]` (file altered after signing). |
| `ERR_REPLAY_DETECTED` | File (R14) | XML, CSV | Manifest `nonce` or file `sha256` was already imported previously. |
| `ERR_CORRUPTED_ROW` | Row | CSV | CSV row does not have exactly 7 columns or XML record is malformed. |
| `ERR_BAD_ID` | Field | XML, CSV | `studentNo` / `StudentNo` does not match allow-list regex `^\d{4}-\d{5}$`. |
| `ERR_UNKNOWN_STUDENT` | Field | XML, CSV | Student ID is well-formed but does not exist in Registrar `valid_student_ids`. |
| `ERR_BAD_NAME` | Field | XML, CSV | Name fails required source format (`LAST, First M.` for XML; `Last, First` for CSV) or contains illegal characters. |
| `ERR_INVALID_PROGRAM` | Field | XML | `<program>` is not in the Registrar/Library program allow-list (e.g., `BSHM`). |
| `ERR_INVALID_DATE` | Field | XML, CSV | Date fails `strptime` calendar validation (e.g., `31/09/2026`, `2026-13-01`). |
| `ERR_EMPTY_DATE` | Field | CSV | `LastPaymentDate` is empty or whitespace-only. |
| `ERR_NEGATIVE_FINE` | Field | XML | `<unpaidFines>` is negative (`< 0.00`, e.g., `-5.00`). |
| `ERR_DUPLICATE_CARD` | Batch | XML | Duplicate `@card` or duplicate borrower entry for a `studentNo` already seen in the same XML batch. |
| `ERR_DUPLICATE_STUDENT` | Batch | CSV | Duplicate `StudentNo` already seen in the same CSV batch. |
| `ERR_FORMATTED_AMOUNT` | Field | CSV | Numeric monetary field contains thousands separators/commas (e.g., `"10,450.50"`). |
| `ERR_NON_NUMERIC_AMOUNT` | Field | XML, CSV | Numeric field is empty or contains non-numeric text (e.g., `"abc"`, `"x"`, `"N/A"`). |
| `ERR_NEGATIVE_AMOUNT` | Field | XML, CSV | Quantity or balance field is `< 0`. |

### Reject Log Entry Format (JSON Lines / Structured Dict)

Every rejected file (with `row_index: null` and `student_id_raw: ""`) or rejected row produces one structured log entry with these exact 6 fields:

| Field | Type | Description |
|---|---|---|
| `timestamp` | `string` (ISO-8601) | Timestamp when the rejection was recorded (e.g., `"2026-11-27T19:30:00+08:00"`). |
| `source_file` | `string` | Basename of the import file being processed (e.g., `"library_export_2026-11-20.xml"`). |
| `row_index` | `integer \| null` | 1-based record index within the file (`null` for file-level R14 rejections). |
| `student_id_raw` | `string` | Raw student ID string extracted from the row (or `""` if missing/file-level). |
| `error_code` | `string` | Standardized error code from the catalog above (e.g., `"ERR_INVALID_DATE"`). |
| `reason` | `string` | Human-readable explanation naming the offending field and value. |

---

## 6. Sample Transformations (Valid & Rejected)

### 6.1 Valid Library XML `<borrower>` → `clearances` Row (HOLD)

**Input (`library_export_2026-11-20.xml`, row 2):**
```xml
<borrower card="LIB-0002">
  <name>MORALES, Ana C.</name>
  <studentNo>2025-81367</studentNo>
  <program>BSED-MATH</program>
  <yearLevel>2</yearLevel>
  <email>ana.morales@dnsc.edu.ph</email>
  <lastBorrowed>09/09/2026</lastBorrowed>
  <unreturnedBooks>1</unreturnedBooks>
  <unpaidFines>40.50</unpaidFines>
</borrower>
```

**Output (`clearances` table row):**
```json
{
  "student_id": "2025-81367",
  "office": "Library",
  "status": "HOLD",
  "reason": "1 unreturned book(s); unpaid fine of PHP 40.50",
  "updated_by": "importer:library",
  "updated_at": "2026-11-27T19:30:00+08:00"
}
```

### 6.2 Rejected Library XML `<borrower>` → Reject Log Entry

**Input (`library_export_2026-11-20.xml`, row 28):**
```xml
<borrower card="LIB-0028">
  <name>TORRES, Ana B.</name>
  <studentNo>2024-99999</studentNo>
  <program>BSHM</program>
  <yearLevel>3</yearLevel>
  <email>ana.torres@dnsc.edu.ph</email>
  <lastBorrowed>31/09/2026</lastBorrowed>
  <unreturnedBooks>0</unreturnedBooks>
  <unpaidFines>15.00</unpaidFines>
</borrower>
```

**Output (reject log entry — fails `ERR_UNKNOWN_STUDENT`, `ERR_INVALID_PROGRAM`, and `ERR_INVALID_DATE`):**
```json
{
  "timestamp": "2026-11-27T19:30:00+08:00",
  "source_file": "library_export_2026-11-20.xml",
  "row_index": 28,
  "student_id_raw": "2024-99999",
  "error_code": "ERR_INVALID_DATE",
  "reason": "Invalid calendar date in <lastBorrowed>: '31/09/2026' (also unknown student '2024-99999' and disallowed program 'BSHM')"
}
```

### 6.3 Valid Accounting CSV Line → `clearances` Row (CLEARED)

**Input (`accounting_balances_2026-11-20.csv`, line 2 / data row 1):**
```csv
2026-29417,"Navarro, Mark",1S 2026-2027,"9,200.00","9,200.00",0.00,2026-09-11
```

**Output (`clearances` table row):**
```json
{
  "student_id": "2026-29417",
  "office": "Accounting",
  "status": "CLEARED",
  "reason": "",
  "updated_by": "importer:accounting",
  "updated_at": "2026-11-27T19:30:00+08:00"
}
```

### 6.4 Rejected Accounting CSV Line → Reject Log Entry

**Input (`accounting_balances_2026-11-20.csv`, line 8 / data row 7):**
```csv
2025-93355,"Flores, Nicole",1S 2026-2027,"10,450.50",0.00,"10,450.50",
```

**Output (reject log entry — strict amount/date validation):**
```json
{
  "timestamp": "2026-11-27T19:30:00+08:00",
  "source_file": "accounting_balances_2026-11-20.csv",
  "row_index": 7,
  "student_id_raw": "2025-93355",
  "error_code": "ERR_FORMATTED_AMOUNT",
  "reason": "Formatted amount with thousands separator in Balance: '10,450.50' (and empty LastPaymentDate)"
}
```
