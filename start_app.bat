@echo off
REM Activate virtual environment if you have one (optional)
REM call venv\Scripts\activate

echo Starting the Flask server...
set FLASK_APP=app.py
set FLASK_ENV=production
flask run --host=0.0.0.0 --port=5000
pause
