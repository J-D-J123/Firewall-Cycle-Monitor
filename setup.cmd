@echo off
REM One-time setup: create the Python engine environment and install Electron.
cd /d "%~dp0"

echo ============================================
echo  Request Cycle Monitor - setup
echo ============================================

echo.
echo [1/3] Creating Python 3.12 virtual environment...
py -3.12 -m venv engine\.venv
if errorlevel 1 (
  echo Could not create the venv with "py -3.12". Trying "python"...
  python -m venv engine\.venv
)

echo.
echo [2/3] Installing engine dependencies (mitmproxy, fastapi, ...)...
engine\.venv\Scripts\python.exe -m pip install --upgrade pip
engine\.venv\Scripts\python.exe -m pip install -r engine\requirements.txt

echo.
echo [3/3] Installing the Electron UI...
cd app
call npm install
cd ..

echo.
echo Setup complete. Run start.cmd to launch.
pause
