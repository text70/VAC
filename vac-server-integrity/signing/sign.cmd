@echo off
REM sign.cmd -- Authenticode signing gate for VAC build artifacts.
REM
REM Signing identity comes from env vars so the gate can run with a self-signed
REM test cert (dev) or a real trusted identity (production) without script edits:
REM
REM   set VAC_SIGN_P12=C:\path\code-signing.p12
REM   set VAC_SIGN_PASS=yourpassword
REM   set VAC_SIGN_TIMESTAMP=http://timestamp.digicert.com   (optional, default below)
REM   set VAC_SIGN_CAFILE=C:\path\signing-cert.crt            (optional; see below)
REM
REM Behavior:
REM   - If VAC_SIGN_P12 is NOT set   -> warn "UNSIGNED" and exit 0 (dev builds allowed)
REM   - If VAC_SIGN_P12 IS set       -> sign + verify, exit 1 on any failure (ENFORCED)
REM
REM Verification trust anchor:
REM   - Self-signed test certs are their own CA, so pass the leaf cert as
REM     VAC_SIGN_CAFILE (gen-test-cert.sh emits <p12>.crt next to the p12).
REM   - If VAC_SIGN_CAFILE is not set but %VAC_SIGN_P12%.crt exists, it is used.
REM   - Production certs (MS Trusted Signing / EV) may verify without -CAfile.
REM
REM TODO (production): replace self-signed test cert with Microsoft Trusted Signing
REM (~$10/mo Azure service, OS-trusted) or a real EV cert (required for kernel-mode
REM driver attestation signing via Partner Center). No script change needed -- just
REM point VAC_SIGN_P12 at the trusted identity.
REM
REM Usage: call sign.cmd <target-file>

setlocal

if "%~1"=="" (
    echo [sign] ERROR: no target file specified
    exit /b 2
)
if not exist "%~1" (
    echo [sign] ERROR: target not found: %~1
    exit /b 2
)

if not defined VAC_SIGN_P12 (
    echo [sign] WARNING: VAC_SIGN_P12 not set -- artifact left UNSIGNED. Not trusted by Windows.
    echo [sign]   Test pipeline:  set VAC_SIGN_P12=signing\test-cert.p12 ^& set VAC_SIGN_PASS=vac-test
    echo [sign]   Production:     Microsoft Trusted Signing or EV cert (see AGENTS.md).
    exit /b 0
)
if not exist "%VAC_SIGN_P12%" (
    echo [sign] ERROR: VAC_SIGN_P12 not found: %VAC_SIGN_P12%
    exit /b 1
)

set "TS=%VAC_SIGN_TIMESTAMP%"
if not defined TS set "TS=http://timestamp.digicert.com"

set "CAFILE=%VAC_SIGN_CAFILE%"
if not defined CAFILE if exist "%VAC_SIGN_P12%.crt" set "CAFILE=%VAC_SIGN_P12%.crt"

echo [sign] Signing %~1 with %VAC_SIGN_P12% ...
osslsigncode sign ^
    -pkcs12 "%VAC_SIGN_P12%" ^
    -pass "%VAC_SIGN_PASS%" ^
    -t "%TS%" ^
    -in "%~1" ^
    -out "%~1.signed"
if errorlevel 1 (
    echo [sign] ERROR: signing failed
    exit /b 1
)

echo [sign] Verifying %~1 ...
if defined CAFILE (
    echo [sign]   trust anchor: %CAFILE%
    osslsigncode verify -in "%~1.signed" -CAfile "%CAFILE%"
) else (
    osslsigncode verify -in "%~1.signed"
)
if errorlevel 1 (
    echo [sign] ERROR: verification failed
    del /q "%~1.signed" >nul 2>&1
    exit /b 1
)

move /y "%~1.signed" "%~1" >nul
echo [sign] OK: %~1 signed and verified
exit /b 0
