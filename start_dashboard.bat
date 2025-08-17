@echo off
echo Starting Meshtastic Analytics Dashboard...
echo.
echo Make sure the GeneralListener.py is running in another terminal to generate data.
echo.
echo Dashboard will be available at: http://localhost:8501
echo.
call .venv\Scripts\activate.bat
streamlit run meshtastic_dashboard.py
pause
