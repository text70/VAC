@echo off
REM Build vac-setup.exe installer
REM
REM Prerequisites:
REM   1. Inno Setup 6+ installed
REM   2. vac.sys built (run kmod-win\build.cmd in WDK prompt)
REM   3. vac-daemon-win.exe cross-compiled (cargo build --release --target x86_64-pc-windows-gnu)
REM   4. EV code-signing certificate installed (optional, for production)
REM
REM Steps:
REM   1. Copy built files to Source\ folder
REM   2. Run this script
REM   3. Built installer in Output\vac-setup.exe
REM
REM Production signing:
REM   signtool sign /fd sha256 /a /tr http://timestamp.digicert.com /td sha256 Output\vac-setup.exe

setlocal

set SCRIPT_DIR=%~dp0
set SOURCE_DIR=%SCRIPT_DIR%Source

if not exist "%SOURCE_DIR%" mkdir "%SOURCE_DIR%"

echo Copying vac.sys from kmod-win...
if exist "%SCRIPT_DIR%..\kmod-win\x64\Release\vac.sys" (
    copy /Y "%SCRIPT_DIR%..\kmod-win\x64\Release\vac.sys" "%SOURCE_DIR%\vac.sys"
) else (
    echo WARNING: vac.sys not found. Build with kmod-win\build.cmd first.
    echo Place a prebuilt vac.sys in %SOURCE_DIR%
)

echo Copying vac-daemon-win.exe from cross-compile output...
if exist "%SCRIPT_DIR%..\target\x86_64-pc-windows-gnu\release\vac-daemon-win.exe" (
    copy /Y "%SCRIPT_DIR%..\target\x86_64-pc-windows-gnu\release\vac-daemon-win.exe" "%SOURCE_DIR%\vac-daemon-win.exe"
) else (
    echo WARNING: vac-daemon-win.exe not found.
    echo Build with: cargo build --release --target x86_64-pc-windows-gnu -p vac-daemon-win
    echo Place a prebuilt vac-daemon-win.exe in %SOURCE_DIR%
)

echo Building installer...
iscc "%SCRIPT_DIR%vac-setup.iss"
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo.
echo Installer built: %SCRIPT_DIR%Output\vac-setup.exe
echo.
echo To sign (production):
echo   signtool sign /fd sha256 /a /tr http://timestamp.digicert.com /td sha256 "%SCRIPT_DIR%Output\vac-setup.exe"
echo.