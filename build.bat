@echo off
rem Builds dist\DiskDetective.exe (a single file, no Python needed to run it).
rem Requires Python 3.9+ with Tk (the normal python.org installer includes it).
setlocal
cd /d "%~dp0"

set VENV=%TEMP%\diskdetective-build
if not exist "%VENV%\Scripts\python.exe" (
    python -m venv "%VENV%" || goto :fail
    "%VENV%\Scripts\python.exe" -m pip install --quiet pyinstaller || goto :fail
)

rem the icon is generated with the standard library only; skip if it already exists
if not exist icon.ico ( python make_icon.py || goto :fail )

"%VENV%\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --noconsole ^
    --name DiskDetective --icon "%~dp0icon.ico" --distpath "%~dp0dist" --workpath "%VENV%\work" --specpath "%VENV%\spec" ^
    diskdetective.py || goto :fail

echo.
echo Done: %~dp0dist\DiskDetective.exe
exit /b 0

:fail
echo.
echo Build failed.
exit /b 1
