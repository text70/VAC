@echo off
REM Build vac-setup.exe installer
REM
REM Prerequisites:
REM   1. Inno Setup 6+ installed
REM   2. vac.sys built (run kmod-win\build.cmd in WDK prompt)
REM   3. vac-daemon-win.exe cross-compiled (cargo build --release --target x86_64-pc-windows-gnu)
REM
REM Signing gate (optional but enforced-when-enabled):
REM   set VAC_SIGN_P12=C:\path\code-signing.p12
REM   set VAC_SIGN_PASS=yourpassword
REM   call installer\build.cmd
REM
REM   Self-signed test cert (pipeline testing only):
REM     bash signing\gen-test-cert.sh            (Linux; produces signing\test-cert.p12)
REM     set VAC_SIGN_P12=signing\test-cert.p12
REM     set VAC_SIGN_PASS=vac-test
REM
REM   Production: Microsoft Trusted Signing (Azure, ~$10/mo) or a real EV cert.
REM   Without VAC_SIGN_P12 set, the installer is built UNSIGNED with a warning.
REM   TODO: switch production signing to Microsoft Trusted Signing.
REM
REM Steps:
REM   1. Copy built files to Source\ folder
REM   2. Run this script
REM   3. Built installer in Output\vac-setup.exe

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
    echo.
    echo Applying signing gate to embedded daemon...
    call "%SCRIPT_DIR%..\signing\sign.cmd" "%SOURCE_DIR%\vac-daemon-win.exe"
    if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
) else (
    echo WARNING: vac-daemon-win.exe not found.
    echo Build with: cargo build --release --target x86_64-pc-windows-gnu -p vac-daemon-win
    echo Place a prebuilt vac-daemon-win.exe in %SOURCE_DIR%
)

echo Building installer...
iscc "%SCRIPT_DIR%vac-setup.iss"
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo.
echo Applying signing gate...
call "%SCRIPT_DIR%..\signing\sign.cmd" "%SCRIPT_DIR%Output\vac-setup.exe"
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo.
echo Installer built: %SCRIPT_DIR%Output\vac-setup.exe
echo.