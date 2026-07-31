@echo off
REM Build vac.sys from kmod-win/
REM Requires WDK 10/11 (Windows Driver Kit) installed, run from a
REM "x64 Native Tools Command Prompt for VS 2022" (or similar).
REM
REM Usage:  build.cmd
REM Output: x64\Release\vac.sys
REM         x64\Release\vac.cat  (attestation-sign-ready CAB)
REM
REM Signing gate (optional but enforced-when-enabled):
REM   set VAC_SIGN_P12=C:\path\code-signing.p12
REM   set VAC_SIGN_PASS=yourpassword
REM   call kmod-win\build.cmd
REM
REM   Self-signed test cert (pipeline testing only):
REM     bash signing\gen-test-cert.sh            (Linux; produces signing\test-cert.p12)
REM     set VAC_SIGN_P12=signing\test-cert.p12
REM     set VAC_SIGN_PASS=vac-test
REM
REM   Production driver trust is Microsoft attestation signing (Partner Center),
REM   which requires a real EV cert -- see the "Production signing" section below.
REM   TODO: switch production signing to Microsoft Trusted Signing.

setlocal enabledelayedexpansion

set BIN_DIR=%~dp0x64\Release
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

echo [vac] Compiling ...
cl /nologo /c /O2 /GS- /W4 /WX /wd4102 /wd4201 /wd4706 /Fo"%BIN_DIR%\vac.obj" %~dp0vac.c
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [vac] Linking ...
link /nologo /driver /subsystem:native /entry:DriverEntry /out:"%BIN_DIR%\vac.sys" "%BIN_DIR%\vac.obj" ntoskrnl.lib
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo.
echo [vac] Applying signing gate (local Authenticode test signature only)...
call "%~dp0..\signing\sign.cmd" "%BIN_DIR%\vac.sys"
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
echo.
echo [vac] To sign for production (attestation signing):
echo  1. Create a CAB containing vac.sys + INF
echo  2. EV-sign the CAB: signtool sign /fd sha256 /a /tr http://timestamp.digicert.com
echo  3. Submit via Partner Center Hardware Dashboard
echo  4. Download Microsoft-signed result
echo  5. NOTE: attestation requires a real EV cert. TODO: Microsoft Trusted Signing
echo     is a cheaper alternative for user-mode trust; kernel drivers still need EV.
echo.
echo [vac] To install on test machine (test-signing mode only):
echo  bcdedit /set testsigning on
echo  sc create Vac type= kernel binPath= "%BIN_DIR%\vac.sys"
echo  sc start Vac
echo.
echo [vac] Done.