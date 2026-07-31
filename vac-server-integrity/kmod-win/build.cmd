@echo off
REM Build vac.sys from kmod-win/
REM Requires WDK 10/11 (Windows Driver Kit) installed, run from a
REM "x64 Native Tools Command Prompt for VS 2022" (or similar).
REM
REM Usage:  build.cmd
REM Output: x64\Release\vac.sys
REM         x64\Release\vac.cat  (attestation-sign-ready CAB)

setlocal enabledelayedexpansion

set BIN_DIR=%~dp0x64\Release
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

echo [vac] Compiling ...
cl /nologo /c /O2 /GS- /W4 /WX /wd4102 /wd4201 /wd4706 /Fo"%BIN_DIR%\vac.obj" %~dp0vac.c
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [vac] Linking ...
link /nologo /driver /subsystem:native /entry:DriverEntry /out:"%BIN_DIR%\vac.sys" "%BIN_DIR%\vac.obj" ntoskrnl.lib
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [vac] Signed: %BIN_DIR%\vac.sys
echo.
echo [vac] To sign for production (attestation signing):
echo  1. Create a CAB containing vac.sys + INF
echo  2. EV-sign the CAB: signtool sign /fd sha256 /a /tr http://timestamp.digicert.com
echo  3. Submit via Partner Center Hardware Dashboard
echo  4. Download Microsoft-signed result
echo.
echo [vac] To install on test machine (test-signing mode only):
echo  bcdedit /set testsigning on
echo  sc create Vac type= kernel binPath= "%BIN_DIR%\vac.sys"
echo  sc start Vac
echo.
echo [vac] Done.