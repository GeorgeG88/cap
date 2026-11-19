@echo off
REM Start the Firewall Log Analyzer on Windows, then open http://127.0.0.1:5000
REM Keep this window open while using the dashboard; closing it stops the app.
cd /d "%~dp0"
if not exist venv\Scripts\activate.bat (
    echo Run setup.bat first.
    pause
    exit /b 1
)
call venv\Scripts\activate.bat
REM Open the dashboard in the default browser (the page may need a second to appear).
start "" http://127.0.0.1:5000
python run.py
pause
