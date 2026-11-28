"""DNSC e-Clearance Hub - Flask REST API (R7, R10-R16)."""
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, Response, g, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

import clients

load_dotenv()

VALID_OFFICES = {"Registrar", "Library", "Accounting", "Student Affairs"}
VALID_STATUSES = {"CLEARED", "HOLD"}
VALID_FORMATS = {"csv", "json", "xml"}
STUDENT_ID_RE = re.compile(r"^\d{4}-\d{5}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,40}$")

app = Flask(__name__, static_folder="static", static_url_path="")


def _secret_key():
    key = os.environ.get("HUB_SECRET_KEY", "")
    if not key:
        raise RuntimeError("HUB_SECRET_KEY environment variable is required")
    return key.encode("utf-8")


def _db_path():
    return os.environ.get("DB_PATH", "clearance.db")


def get_db():
    if "db" not in g:
        db_file = _db_path()
        if not os.path.exists(db_file):
            init_db(db_file)
        g.db = sqlite3.connect(db_file)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(db_path=None):
    """Initialize SQLite schema and seed demo users if empty."""
    path = db_path or _db_path()
    schema_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
    conn = sqlite3.connect(path)
    with open(schema_file, encoding="utf-8") as f:
        conn.executescript(f.read())

    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        seed_pw = os.environ.get("DEV_SEED_PASSWORD", "ChangeMeDev123!")
        pw_hash = generate_password_hash(seed_pw, method="pbkdf2:sha256")
        demo_users = [
            ("admin", pw_hash, "admin", None, None),
            ("staff_lib", pw_hash, "staff", "Library", None),
            ("staff_acc", pw_hash, "staff", "Accounting", None),
            ("staff_osa", pw_hash, "staff", "Student Affairs", None),
            ("2023-59928", pw_hash, "student", None, "2023-59928"),
        ]
        conn.executemany(
            "INSERT INTO users (username, password_hash, role, office, student_id) VALUES (?, ?, ?, ?, ?)",
            demo_users,
        )

    if conn.execute("SELECT COUNT(*) FROM students").fetchone()[0] == 0:
        seed_json = os.path.join(os.path.dirname(os.path.abspath(__file__)), "starter_kit", "registrar_students.json")
        if os.path.exists(seed_json):
            with open(seed_json, encoding="utf-8") as f:
                _upsert_students(conn, json.load(f).get("students", []), "system_seed")
    conn.commit()
    conn.close()


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def sign_token(payload: dict, ttl_seconds: int = 3600) -> str:
    body = dict(payload)
    body["exp"] = int(time.time()) + ttl_seconds
    raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(_secret_key(), raw, hashlib.sha256).digest()
    return f"{_b64_encode(raw)}.{_b64_encode(sig)}"


def verify_token(token: str):
    """Verify HMAC signature and expiration; return payload dict or None."""
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        raw = _b64_decode(raw_b64)
        sig = _b64_decode(sig_b64)
    except Exception:
        return None
    expected = hmac.new(_secret_key(), raw, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except ValueError:
        return None
    if not isinstance(payload, dict) or payload.get("exp", 0) < int(time.time()):
        return None
    return payload


def mask_student_id(student_id: str) -> str:
    """Mask middle characters of a student ID (e.g. 2023-59928 -> 2023-***28)."""
    if len(student_id) >= 7 and "-" in student_id:
        prefix, rest = student_id.split("-", 1)
        return f"{prefix}-***{rest[-2:]}"
    return "***"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _log_audit(db, who: str, action: str, target: str, details: str = ""):
    db.execute(
        "INSERT INTO audit_log (who, action, target, details, timestamp) VALUES (?, ?, ?, ?, ?)",
        (who, action, target, details, _now_iso()),
    )


def require_auth(roles=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "Missing or invalid Authorization header"}), 401
            payload = verify_token(auth[7:].strip())
            if payload is None:
                return jsonify({"error": "Invalid or expired token"}), 401
            if roles and payload.get("role") not in roles:
                return jsonify({"error": "Forbidden for your role"}), 403
            g.user = payload
            return fn(*args, **kwargs)
        return wrapper
    return decorator


@app.after_request
def add_cors_headers(resp):
    origin = os.environ.get("CORS_ORIGIN", "*")
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/")
def index():
    if os.path.exists(os.path.join(app.static_folder, "index.html")):
        return send_from_directory(app.static_folder, "index.html")
    return jsonify({"service": "DNSC e-Clearance Hub API", "status": "ok"})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    if not USERNAME_RE.fullmatch(username) or not password:
        return jsonify({"error": "Invalid username or password format"}), 400

    row = get_db().execute(
        "SELECT username, password_hash, role, office, student_id FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = sign_token({
        "sub": row["username"],
        "role": row["role"],
        "office": row["office"],
        "student_id": row["student_id"],
    })
    return jsonify({
        "token": token,
        "user": {
            "username": row["username"],
            "role": row["role"],
            "office": row["office"],
            "student_id": row["student_id"],
        },
    })


@app.route("/api/auth/me", methods=["GET"])
@require_auth()
def auth_me():
    return jsonify({"user": g.user})


def _get_student_clearance(db, student_id: str):
    student = db.execute("SELECT * FROM students WHERE student_id = ?", (student_id,)).fetchone()
    if student is None:
        return None, None, None
    rows = db.execute(
        "SELECT office, status, reason, updated_by, updated_at FROM clearances WHERE student_id = ? ORDER BY office",
        (student_id,),
    ).fetchall()
    offices = [dict(r) for r in rows]
    cleared_offices = {o["office"] for o in offices if o["status"] == "CLEARED"}
    overall = "CLEARED" if cleared_offices == VALID_OFFICES else "HOLD"
    return dict(student), offices, overall


@app.route("/api/clearance/me", methods=["GET"])
@require_auth(roles={"student"})
def clearance_me():
    sid = g.user.get("student_id")
    if not sid:
        return jsonify({"error": "No student_id linked to account"}), 400
    student, offices, overall = _get_student_clearance(get_db(), sid)
    if student is None:
        return jsonify({"error": "Student record not found (sync Registrar first)"}), 404
    return jsonify({
        "student": student,
        "overall_status": overall,
        "deadline": clients.compute_deadline(),
        "offices": offices,
    })


@app.route("/api/clearance/slip", methods=["GET"])
@require_auth(roles={"student"})
def clearance_slip():
    sid = g.user.get("student_id")
    student, _offices, overall = _get_student_clearance(get_db(), sid)
    if student is None:
        return jsonify({"error": "Student record not found"}), 404
    if overall != "CLEARED":
        return jsonify({"error": "Clearance not complete", "overall_status": overall}), 409

    slip_token = sign_token({"type": "slip", "student_id": sid, "overall_status": "CLEARED"}, ttl_seconds=86400)
    return jsonify({"student_id": sid, "overall_status": "CLEARED", "slip_token": slip_token})


@app.route("/api/clearance/verify", methods=["GET"])
def clearance_verify():
    token = request.args.get("token", "").strip()
    if not token or len(token) > 512:
        return jsonify({"valid": False, "error": "Missing or invalid token"}), 400
    payload = verify_token(token)
    if payload is None or payload.get("type") != "slip":
        return jsonify({"valid": False, "error": "Invalid or expired clearance slip"}), 401
    return jsonify({
        "valid": True,
        "student_id": payload["student_id"],
        "overall_status": payload["overall_status"],
    })


@app.route("/api/staff/students", methods=["GET"])
@require_auth(roles={"staff", "admin"})
def staff_students():
    q = request.args.get("q", "").strip()
    if len(q) > 60:
        return jsonify({"error": "Query too long"}), 400
    db = get_db()
    if q:
        like = f"%{q}%"
        rows = db.execute(
            "SELECT * FROM students WHERE student_id LIKE ? OR name LIKE ? ORDER BY student_id",
            (like, like),
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM students ORDER BY student_id").fetchall()

    result = []
    for s in rows:
        _, offices, overall = _get_student_clearance(db, s["student_id"])
        result.append({**dict(s), "overall_status": overall, "offices": offices})
    return jsonify({"students": result})


@app.route("/api/staff/clearance", methods=["POST"])
@require_auth(roles={"staff", "admin"})
def staff_update_clearance():
    data = request.get_json(silent=True) or {}
    sid = str(data.get("student_id", "")).strip()
    office = str(data.get("office") or g.user.get("office") or "").strip()
    status = str(data.get("status", "")).strip().upper()
    reason = str(data.get("reason", "")).strip()

    if not STUDENT_ID_RE.fullmatch(sid):
        return jsonify({"error": "Invalid student_id format (expected YYYY-NNNNN)"}), 400
    if office not in VALID_OFFICES:
        return jsonify({"error": "Invalid office"}), 400
    if g.user["role"] == "staff" and g.user.get("office") and g.user["office"] != office:
        return jsonify({"error": "Staff can only update their own office"}), 403
    if status not in VALID_STATUSES:
        return jsonify({"error": "status must be CLEARED or HOLD"}), 400
    if len(reason) > 200:
        return jsonify({"error": "reason must be <= 200 chars"}), 400

    db = get_db()
    if db.execute("SELECT 1 FROM students WHERE student_id = ?", (sid,)).fetchone() is None:
        return jsonify({"error": "Student not found"}), 404

    now = _now_iso()
    db.execute(
        """INSERT INTO clearances (student_id, office, status, reason, updated_by, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(student_id, office) DO UPDATE SET
             status = excluded.status,
             reason = excluded.reason,
             updated_by = excluded.updated_by,
             updated_at = excluded.updated_at""",
        (sid, office, status, reason, g.user["sub"], now),
    )
    _log_audit(db, g.user["sub"], f"SET_{status}", sid, f"{office}: {reason}")
    db.commit()
    return jsonify({"student_id": sid, "office": office, "status": status, "reason": reason})


def _upsert_students(db, students, actor: str):
    """Upsert Registrar student records and initialize per-office clearance rows."""
    now = _now_iso()
    for s in students:
        sid = s["student_id"]
        reg_status = s.get("status", "ENROLLED")
        full_name = s.get("name") or f"{s['last_name']}, {s['first_name']} {s.get('middle_initial', '')}.".strip()
        program = s.get("program_code") or s.get("program", "")
        year = int(s.get("year_level") or s.get("year", 1))
        db.execute(
            """INSERT INTO students (student_id, name, program, year, email, registrar_status)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(student_id) DO UPDATE SET
                 name = excluded.name,
                 program = excluded.program,
                 year = excluded.year,
                 email = excluded.email,
                 registrar_status = excluded.registrar_status""",
            (sid, full_name, program, year, s["email"], reg_status),
        )
        # LOA students are placed on HOLD at the Registrar office
        office_status = "HOLD" if reg_status == "LOA" else "CLEARED"
        reason = "On Leave of Absence (LOA)" if reg_status == "LOA" else ""
        db.execute(
            """INSERT INTO clearances (student_id, office, status, reason, updated_by, updated_at)
               VALUES (?, 'Registrar', ?, ?, ?, ?)
               ON CONFLICT(student_id, office) DO UPDATE SET
                 status = excluded.status, reason = excluded.reason,
                 updated_by = excluded.updated_by, updated_at = excluded.updated_at""",
            (sid, office_status, reason, actor, now),
        )
        for office in ("Library", "Accounting", "Student Affairs"):
            db.execute(
                """INSERT OR IGNORE INTO clearances (student_id, office, status, reason, updated_by, updated_at)
                   VALUES (?, ?, 'HOLD', 'Pending clearance', 'system', ?)""",
                (sid, office, now),
            )


@app.route("/api/admin/sync-registrar", methods=["POST"])
@require_auth(roles={"admin"})
def admin_sync_registrar():
    try:
        students = clients.fetch_all_students()
    except clients.ExternalAPIError as exc:
        return jsonify({"error": str(exc)}), 502

    db = get_db()
    _upsert_students(db, students, g.user["sub"])
    _log_audit(db, g.user["sub"], "SYNC_REGISTRAR", "students", f"Synced {len(students)} students")
    db.commit()
    return jsonify({"synced": len(students)})


@app.route("/api/admin/audit", methods=["GET"])
@require_auth(roles={"admin"})
def admin_audit():
    rows = get_db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
    return jsonify({"audit_log": [dict(r) for r in rows]})


@app.route("/api/admin/reports", methods=["GET"])
@require_auth(roles={"admin"})
def admin_reports():
    fmt = request.args.get("format", "json").strip().lower()
    if fmt not in VALID_FORMATS:
        return jsonify({"error": "format must be csv, json, or xml"}), 400

    db = get_db()
    rows = db.execute("SELECT student_id, program, year, registrar_status FROM students ORDER BY student_id").fetchall()
    report = []
    for s in rows:
        _, offices, overall = _get_student_clearance(db, s["student_id"])
        holds = "; ".join(f"{o['office']}: {o['reason']}" for o in offices if o["status"] == "HOLD")
        report.append({
            "masked_id": mask_student_id(s["student_id"]),
            "program": s["program"],
            "year": s["year"],
            "overall_status": overall,
            "holds": holds,
        })

    if fmt == "json":
        return jsonify({"report": report})
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["masked_id", "program", "year", "overall_status", "holds"])
        writer.writeheader()
        writer.writerows(report)
        return Response(buf.getvalue(), mimetype="text/csv")

    root = ET.Element("clearance_report")
    for item in report:
        el = ET.SubElement(root, "student")
        for k, v in item.items():
            child = ET.SubElement(el, k)
            child.text = str(v)
    return Response(ET.tostring(root, encoding="unicode"), mimetype="application/xml")


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
