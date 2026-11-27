CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('student', 'staff', 'admin')),
    office TEXT,
    student_id TEXT
);

CREATE TABLE IF NOT EXISTS students (
    student_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    program TEXT NOT NULL,
    year INTEGER NOT NULL,
    email TEXT NOT NULL,
    registrar_status TEXT NOT NULL
);

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

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    who TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL
);
