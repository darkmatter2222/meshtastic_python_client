@echo off
echo Starting Meshtastic Listener...
echo.
echo This will start collecting data for the dashboard.
echo.
call .venv\Scripts\activate.bat
pip install -r requirements.txt
python GeneralListener.py
pause
