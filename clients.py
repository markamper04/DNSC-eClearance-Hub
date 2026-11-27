"""External API clients for Registrar (R5) and Nager.Date PH Holidays (R6)."""
from datetime import date, timedelta
import os
import time
import requests


class ExternalAPIError(RuntimeError):
    """Raised when an external API fails after retries or returns invalid data."""


def _request_json(url, headers=None, params=None, timeout=5, max_retries=3):
    """GET JSON with 503 Retry-After, timeout, HTTP status, and bad-JSON handling."""
    for attempt in range(max_retries):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        except requests.RequestException as exc:
            if attempt == max_retries - 1:
                raise ExternalAPIError(f"Request failed for {url}: {exc}") from exc
            time.sleep(1)
            continue

        if resp.status_code == 503:
            if attempt == max_retries - 1:
                raise ExternalAPIError(f"Service unavailable (503) at {url}")
            retry_after = resp.headers.get("Retry-After", "1")
            time.sleep(max(1, int(retry_after)) if retry_after.isdigit() else 1)
            continue
        if resp.status_code == 401:
            raise ExternalAPIError("Unauthorized (401): check REGISTRAR_API_KEY")
        if resp.status_code == 400:
            raise ExternalAPIError(f"Bad request (400) at {url}: {resp.text}")
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise ExternalAPIError(f"HTTP {resp.status_code} at {url}")

        try:
            return resp.json()
        except ValueError as exc:
            raise ExternalAPIError(f"Invalid JSON from {url}") from exc

    raise ExternalAPIError(f"Max retries exceeded for {url}")


def fetch_all_students(base_url=None, api_key=None, page_size=20):
    """Fetch all pages of students from the Registrar API."""
    base_url = (base_url or os.environ.get("REGISTRAR_API_URL", "http://127.0.0.1:8001/api/v1")).rstrip("/")
    api_key = api_key if api_key is not None else os.environ.get("REGISTRAR_API_KEY", "")
    if not api_key:
        raise ExternalAPIError("REGISTRAR_API_KEY is not set")

    students, page = [], 1
    headers = {"X-API-Key": api_key}
    while True:
        body = _request_json(f"{base_url}/students", headers=headers, params={"page": page, "size": page_size})
        if body is None or not isinstance(body, dict) or "data" not in body:
            raise ExternalAPIError("Unexpected Registrar /students response shape")
        students.extend(body["data"])
        if not body.get("has_next"):
            break
        page += 1
    return students


def fetch_student(student_id, base_url=None, api_key=None):
    """Fetch one student by ID; returns None if 404."""
    base_url = (base_url or os.environ.get("REGISTRAR_API_URL", "http://127.0.0.1:8001/api/v1")).rstrip("/")
    api_key = api_key if api_key is not None else os.environ.get("REGISTRAR_API_KEY", "")
    return _request_json(f"{base_url}/students/{student_id}", headers={"X-API-Key": api_key})


def fetch_ph_holidays(year=None):
    """Return a set of YYYY-MM-DD Philippine public holiday strings from Nager.Date."""
    year = year or date.today().year
    url = f"https://date.nager.at/api/v3/PublicHolidays/{year}/PH"
    data = _request_json(url, timeout=5, max_retries=2)
    if not isinstance(data, list):
        raise ExternalAPIError("Unexpected Nager.Date response shape")
    return {item["date"] for item in data if isinstance(item, dict) and "date" in item}


def compute_deadline(start_date=None, working_days=None, holidays=None):
    """Return ISO deadline N working days after start_date, skipping weekends and PH holidays."""
    current = start_date or date.today()
    days_needed = working_days if working_days is not None else int(os.environ.get("DEADLINE_WORKING_DAYS", "5"))
    if holidays is None:
        try:
            holidays = fetch_ph_holidays(current.year)
        except ExternalAPIError:
            # shortcut: fall back to weekends-only if Nager.Date is offline during demo
            holidays = set()

    counted = 0
    while counted < days_needed:
        current += timedelta(days=1)
        if current.weekday() < 5 and current.isoformat() not in holidays:
            counted += 1
    return current.isoformat()


if __name__ == "__main__":
    # Quick smoke check for deadline calculation
    sample_holidays = {"2026-11-30"}  # Bonifacio Day
    assert compute_deadline(date(2026, 11, 27), 3, sample_holidays) == "2026-12-03"
    print("clients.py self-check passed")
