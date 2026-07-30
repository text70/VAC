# VAC — Valve Anti-Cheat reconstruction

Windows-only C DLL. Built with Visual Studio 2019 (v142, WinSDK 10.0). Open `VAC.sln` or build `VAC/VAC.vcxproj` from CLI.

## Build

```bash
# Debug 32-bit
msbuild VAC.sln /p:Configuration=Debug /p:Platform=Win32
# Release 64-bit
msbuild VAC.sln /p:Configuration=Release /p:Platform=x64
```

Preprocessor: `VAC_EXPORTS;_WINDOWS;_USRDLL` always defined. No precompiled header for Win32 configs (x64 Debug/Release uses precompiled headers via `pch.h`).

## Conventions

- Every function has a comment with its byte signature from the original disassembly (e.g. `// 83 C8 FF 83 E9 00`). Preserve these when editing — they are the traceability anchor back to the binary.
- All code is C (not C++), even though the original was C++. Headers use `#pragma once`.
- Win32 API functions called through the `winApi` struct (indirection table in `Utils.h:80`) for integrity checking. Do not call Win32 APIs directly.
- Module structs (`SystemInfo`, etc.) are exact layout recreations from reverse engineering — do not reorder fields or change padding.
- Module entrypoints are plain C functions (e.g. `SystemInfo_collectData`), not DllMain exports.

## Architecture

| Directory | Purpose |
|-----------|---------|
| `VAC/` | Project root — `Utils.c/h`, `Vector.c/h` |
| `VAC/Encryption/` | ICE cipher implementation (`Ice.c/h`) |
| `VAC/Modules/DeviceInfo/` | Device enumeration module |
| `VAC/Modules/DriverInfo/` | Driver enumeration module |
| `VAC/Modules/ProcessHandleList/` | Process/handle enumeration (module #2) |
| `VAC/Modules/ProcessMonitor/` | Polymorphic scan module (module #3) |
| `VAC/Modules/ReadModules/` | Module loading/reading utility |
| `VAC/Modules/SystemInfo/` | System info collection (module #1) |

Modules are streamed as separate DLLs from Valve's servers; each one collects data into a fixed-size `DWORD data[2048]` buffer and encrypts it with XOR/ICE before sending.

## No tests / CI

No test framework, no CI config. Verification is manual by diffing against disassembly or checking struct layouts match the original.

#opencode -s ses_04f43069bffeQCrPuzRQV7V0K2

