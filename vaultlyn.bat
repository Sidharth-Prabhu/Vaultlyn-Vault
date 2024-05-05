@echo off
REM Activate the virtual environment
call python -m venv venv
call venv\Scripts\activate
echo "Installing required libraries..."
pip install -r requirements.txt

REM Run the Python script
python main.py
