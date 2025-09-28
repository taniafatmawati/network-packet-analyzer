@echo off
REM Run this batch file as Administrator!
REM It will activate venv and start analyzer.py

echo === Network Packet Analyzer (Windows) ===
cd /d %~dp0

REM Activate virtual environment
if exist venv\Scripts\activate (
    call venv\Scripts\activate
) else (
    echo [!] Virtual environment not found. Please run:
    echo     python -m venv venv
    echo     venv\Scripts\activate
    echo     pip install -r requirements.txt
    pause
    exit /b
)

REM Run analyzer
pause
python -i analyzer.py
