@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [reconkit] creating virtual environment...
  python -m venv .venv
  if errorlevel 1 goto :error
)

if not exist ".venv\.deps-installed" (
  echo [reconkit] installing dependencies...
  ".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 goto :error
  type nul > ".venv\.deps-installed"
)

".venv\Scripts\python.exe" -m reconkit
goto :eof

:error
echo.
echo [reconkit] setup failed. Check that Python 3.10+ is installed and on PATH.
pause
