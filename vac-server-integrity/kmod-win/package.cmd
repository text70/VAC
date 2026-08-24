@echo off
setlocal enabledelayedexpansion
rem ============================================================
rem package.cmd -- build the driver CAB for Microsoft attestation
rem signing via Partner Center (Hardware Dev Center).
rem
rem Prerequisites:
rem   * vac.sys built (run build.cmd first)
rem   * WDK installed: inf2cat.exe + makecab.exe on PATH
rem     (run from an "x64 Native Tools Command Prompt for VS")
rem
rem Output: dist\vac-driver-package.cab  -> submit to Partner Center,
rem         select "Attestation signing", download MS-signed files.
rem ============================================================

set STAGE=%~dp0dist\stage
set DIST=%~dp0dist
set SYS_SRC=%~dp0x64\Release\vac.sys

if not exist "%SYS_SRC%" (
    echo ERROR: %SYS_SRC% not found. Run build.cmd first.
    exit /b 1
)

echo Cleaning staging dirs...
if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%STAGE%"

copy /y "%SYS_SRC%" "%STAGE%\vac.sys" >nul || exit /b 1
copy /y "%~dp0vac.inf" "%STAGE%\vac.inf" >nul || exit /b 1

where inf2cat >nul 2>&1
if errorlevel 1 (
    echo WARNING: inf2cat not found - packaging WITHOUT catalog.
    echo          Install the WDK to produce a submittable package.
) else (
    echo Generating catalog ^(inf2cat^)...
    inf2cat /driver:"%STAGE%" /os:10_X64 /verbose || exit /b 1
)

echo Building CAB...
> "%DIST%\vac.ddf" (
    echo .Option Explicit
    echo .Set CabinetFileCountThreshold=0
    echo .Set FolderFileCountThreshold=0
    echo .Set FolderSizeThreshold=0
    echo .Set MaxCabinetSize=0
    echo .Set MaxDiskFileCount=0
    echo .Set MaxDiskSize=0
    echo .Set CompressionType=MSZIP
    echo .Set Cabinet=on
    echo .Set Compress=on
    echo .Set CabinetNameTemplate=vac-driver-package.cab
    echo .Set DestinationDir="%DIST%"
    echo "%%STAGE%%\vac.sys"
    echo "%%STAGE%%\vac.inf"
)
for %%f in ("%STAGE%\*") do echo "%%f">> "%DIST%\vac.ddf"
makecab /F "%DIST%\vac.ddf" || exit /b 1

echo.
echo SUCCESS: %DIST%\vac-driver-package.cab
echo Next steps:
echo   1. Sign the CAB with your EV cert:
echo        signtool sign /fd sha256 /a /tr http://timestamp.digicert.com /td sha256 dist\vac-driver-package.cab
echo   2. Partner Center ^> Hardware submission ^> upload CAB ^>
echo      select "Attestation signing"
echo   3. Download the signed package and ship vac.cat + vac.sys in the installer.
exit /b 0
