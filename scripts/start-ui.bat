@echo off
rem Opens ProxyHive as an app window (no terminal). Use start-browser.bat to run it in your browser instead.
cd /d "%~dp0.."
start "" pythonw app.py
