@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  echo Creating virtual environment...
  python -m venv .venv
)
call .venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
pause
