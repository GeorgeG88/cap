@echo off
REM One-time setup on Windows: virtual environment, dependencies, database, admin account.
REM Steps: find Python, create the "venv" folder (a private copy of Python for this
REM project), install the packages from requirements.txt, then run "manage.py init",
REM which creates the .env file, the database and asks for the first admin account.

REM Run from the folder this file is in, wherever it was double-clicked from.
cd /d "%~dp0"
REM Prefer the "py" launcher that comes with Python from python.org; fall back to "python".
where py >nul 2>nul && (set PY=py) || (set PY=python)
if not exist venv (
    echo Creating virtual environment...
    %PY% -m venv venv || goto :error
)
call venv\Scripts\activate.bat || goto :error
python -m pip install --upgrade pip >nul
pip install -r requirements.txt || goto :error
python manage.py init || goto :error
echo.
echo Setup complete. Run start.bat to launch the dashboard.
pause
exit /b 0
:error
echo.
echo Setup failed. Make sure Python 3.10+ from python.org is installed and on PATH.
pause
exit /b 1
