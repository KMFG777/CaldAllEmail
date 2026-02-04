@echo off
title تشغيل موقع كالد | Cald
color 0A

echo ===================================================
echo           نظام تشغيل موقع كالد التلقائي
echo ===================================================
echo.

:: Check for py launcher
py --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=py
    goto :FOUND_PYTHON
)

:: Check for python command
python --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=python
    goto :FOUND_PYTHON
)

:: If neither found
color 0C
echo [ERROR] لم يتم العثور على Python!
echo.
echo يرجى التأكد من تثبيت Python من الرابط:
echo https://www.python.org/downloads/
echo.
echo هام: تأكد من وضع علامة صح على "Add Python to PATH" أثناء التثبيت.
echo.
pause
exit /b

:FOUND_PYTHON
echo تم العثور على Python، جاري التحضير...
echo.

echo [1/3] جاري تثبيت المكتبات اللازمة...
%PYTHON_CMD% -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [ERROR] فشل تثبيت المكتبات!
    echo تأكد من اتصالك بالإنترنت.
    pause
    exit /b
)

echo.
echo [2/3] تم التثبيت بنجاح!
echo.
echo [3/3] جاري تشغيل السيرفر...
echo.
echo ===================================================
echo     الموقع يعمل الآن على الرابط التالي:
echo     http://127.0.0.1:5000
echo ===================================================
echo.
echo اضغط Ctrl+C لإيقاف السيرفر
echo.

%PYTHON_CMD% app.py

if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [ERROR] توقف الموقع عن العمل بشكل غير متوقع.
    pause
)

pause
