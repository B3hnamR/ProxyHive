@echo off
rem Builds dist\ProxyHive.exe: one file, no terminal window, with the ProxyHive icon. Python and the dashboard are inside.
rem Needs:  pip install -r requirements-dev.txt
cd /d "%~dp0.."
python scripts\make_version_info.py build\version_info.txt
if errorlevel 1 (echo Could not write the version info & exit /b 1)
python -m PyInstaller --noconfirm --clean --onefile --noconsole --name ProxyHive ^
  --icon "%cd%\assets\proxyhive.ico" --version-file "%cd%\build\version_info.txt" ^
  --add-data "%cd%\web;web" --add-data "%cd%\assets;assets" --add-data "%cd%\sources.txt;." ^
  --collect-all webview --collect-all pythonnet --collect-all clr_loader ^
  --distpath dist --workpath build\pyinstaller --specpath build ^
  app.py
if errorlevel 1 (echo Build failed & exit /b 1)
echo.
echo Done: %cd%\dist\ProxyHive.exe
echo Data (settings, pool, results) is stored next to the .exe.
