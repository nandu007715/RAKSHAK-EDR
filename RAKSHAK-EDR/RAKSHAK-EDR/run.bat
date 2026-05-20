@echo off
echo.
echo  =====================================================
echo   RAKSHAK-EDR - Endpoint Detection and Response
echo  =====================================================
echo.
echo  Installing dependencies...
pip install -r requirements.txt
echo.
echo  Starting server...
echo  Open browser: http://127.0.0.1:5000
echo  Login: admin / admin123
echo.
python app.py
pause
