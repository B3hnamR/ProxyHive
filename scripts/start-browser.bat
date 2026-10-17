@echo off
rem Runs ProxyHive in this terminal and opens it in your browser.
cd /d "%~dp0.."
python app.py --server
pause
