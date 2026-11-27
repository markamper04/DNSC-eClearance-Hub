@echo off
REM DNSC e-Clearance Hub — Scheduled Daily Drop-Folder Import (R2)
REM Example Windows Task Scheduler registration:
REM   schtasks /create /tn "DNSC_eClearance_Daily_Import" /tr "\"%~dp0run_automate.bat\"" /sc daily /st 18:00

cd /d "%~dp0"

if exist ".venv\Scripts\activate.bat" (
    call ".venv\Scripts\activate.bat"
) else if exist "venv\Scripts\activate.bat" (
    call "venv\Scripts\activate.bat"
)

python automate.py %*
exit /b %ERRORLEVEL%
