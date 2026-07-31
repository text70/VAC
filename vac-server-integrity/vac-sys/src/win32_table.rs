// Win32 API indirection table from VAC/Utils.h:80-254
// Exact struct layout recreation with all 173 function pointers + 28 DWORD pad.

#![allow(non_camel_case_types, dead_code, non_snake_case)]

pub type BOOL = i32;
pub type DWORD = u32;
pub type HANDLE = *mut std::ffi::c_void;
pub type HMODULE = HANDLE;
pub type FARPROC = Option<unsafe extern "system" fn() -> isize>;
pub type LPCSTR = *const u8;
pub type LPSTR = *mut u8;
pub type LPCWSTR = *const u16;
pub type LPWSTR = *mut u16;
pub type LPVOID = *mut std::ffi::c_void;
pub type LPCVOID = *const std::ffi::c_void;
pub type PVOID = *mut std::ffi::c_void;
pub type NTSTATUS = i32;
pub type ULONG = u32;
pub type ULONG64 = u64;
pub type UINT = u32;
pub type SIZE_T = usize;
pub type LONG = i32;
pub type DWORD64 = u64;
pub type DWORD_PTR = u64;
pub type UINT_PTR = u64;
pub type BOOLEAN = u8;
pub type HRESULT = i32;
pub type LSTATUS = i32;
pub type HKEY = *mut std::ffi::c_void;
pub type SC_HANDLE = *mut std::ffi::c_void;
pub type HCRYPTMSG = *mut std::ffi::c_void;
pub type HCERTSTORE = *mut std::ffi::c_void;
pub type HCRYPTPROV_LEGACY = *mut std::ffi::c_void;
pub type HDEVINFO = *mut std::ffi::c_void;
pub type HWND = *mut std::ffi::c_void;
pub type HLOCAL = *mut std::ffi::c_void;
pub type PSID = *mut std::ffi::c_void;
pub type LUID = *mut std::ffi::c_void;
pub type PGUID = *mut std::ffi::c_void;
pub type LPCGUID = *const std::ffi::c_void;
pub type PUINT = *mut UINT;
pub type PULONG = *mut ULONG;
pub type PULONG64 = *mut ULONG64;
pub type PDWORD = *mut DWORD;
pub type PLONG = *mut LONG;
pub type PBOOL = *mut BOOL;
pub type PHANDLE = *mut HANDLE;
pub type PFILETIME = *mut std::ffi::c_void;
pub type PULONG_PTR = *mut u64;
pub type ACCESS_MASK = DWORD;

#[repr(C)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: DWORD,
    pub lpSecurityDescriptor: LPVOID,
    pub bInheritHandle: BOOL,
}

pub type LPSECURITY_ATTRIBUTES = *mut SECURITY_ATTRIBUTES;
pub type LPOVERLAPPED = *mut std::ffi::c_void;

pub type PTOKEN_PRIVILEGES = *mut std::ffi::c_void;
pub type LPCONTEXT = *mut std::ffi::c_void;

// Structure types (opaque pointers)
pub type LPMODULEENTRY32W = *mut std::ffi::c_void;
pub type LPPROCESSENTRY32W = *mut std::ffi::c_void;
pub type LPTHREADENTRY32 = *mut std::ffi::c_void;
pub type LPHEAPENTRY32 = *mut std::ffi::c_void;
pub type LPMODULEINFO = *mut std::ffi::c_void;
pub type LPBY_HANDLE_FILE_INFORMATION = *mut std::ffi::c_void;
pub type LPSYSTEM_INFO = *mut std::ffi::c_void;
pub type LPOSVERSIONINFOEXA = *mut std::ffi::c_void;
pub type LPOSVERSIONINFOEXW = *mut std::ffi::c_void;
pub type LPENUM_SERVICE_STATUSA = *mut std::ffi::c_void;
pub type LPENUM_SERVICE_STATUSW = *mut std::ffi::c_void;
pub type LPQUERY_SERVICE_CONFIGA = *mut std::ffi::c_void;
pub type LPQUERY_SERVICE_CONFIGW = *mut std::ffi::c_void;
pub type PSP_DEVINFO_DATA = *mut std::ffi::c_void;
pub type PCCERT_CONTEXT = *mut std::ffi::c_void;
pub type PLARGE_INTEGER = *mut i64;
pub type LARGE_INTEGER = i64;
pub type PMEMORY_BASIC_INFORMATION = *mut std::ffi::c_void;
pub type LPSTACKFRAME64 = *mut std::ffi::c_void;
pub type PREAD_PROCESS_MEMORY_ROUTINE64 = *mut std::ffi::c_void;
pub type PFUNCTION_TABLE_ACCESS_ROUTINE64 = *mut std::ffi::c_void;
pub type PGET_MODULE_BASE_ROUTINE64 = *mut std::ffi::c_void;
pub type PTRANSLATE_ADDRESS_ROUTINE64 = *mut std::ffi::c_void;
pub type PVECTORED_EXCEPTION_HANDLER = *mut std::ffi::c_void;
pub type PWSTR = *mut u16;
pub type PCWSTR = *const u16;
pub type PSTR = *mut u8;
pub type PMIB_TCPTABLE = *mut std::ffi::c_void;
pub type PMIB_TCP6TABLE = *mut std::ffi::c_void;
pub type PMIB_UDPTABLE = *mut std::ffi::c_void;
pub type PMIB_UDP6TABLE = *mut std::ffi::c_void;
pub type POBJECT_ATTRIBUTES = *mut std::ffi::c_void;
pub type LPFILE_ID_DESCRIPTOR = *mut std::ffi::c_void;
pub type PWINTRUST_DATA = *mut std::ffi::c_void;
pub type ALG_ID = UINT;

pub type LPCWCH = *const u16;
pub type LPWCH = *mut u16;
pub type LPCCH = *const u8;
pub type PCSTR = *const u8;
pub type PVOID64 = *mut std::ffi::c_void;
pub type LPBYTE = *mut u8;
pub type PBYTE = *mut u8;
pub type ULONG_PTR = u64;
pub type COMPUTER_NAME_FORMAT = i32;
pub type PUCHAR = *mut u8;
pub type USHORT = u16;
pub type PHKEY = *mut HKEY;

pub type REGSAM = DWORD;
pub type FILE_INFO_BY_HANDLE_CLASS = i32;
pub type SYSTEM_INFORMATION_CLASS = i32;
pub type THREADINFOCLASS = i32;
pub type PROCESSINFOCLASS = i32;
pub type OBJECT_INFORMATION_CLASS = i32;
pub type TOKEN_INFORMATION_CLASS = i32;
pub type EXTENDED_NAME_FORMAT = i32;

#[allow(non_snake_case)]
#[repr(C)]
pub struct WinApiTable {
    pub LoadLibraryExA: Option<unsafe extern "system" fn(LPCSTR, HANDLE, DWORD) -> HMODULE>,
    pub GetProcAddress: Option<unsafe extern "system" fn(HMODULE, LPCSTR) -> FARPROC>,
    pub NtOpenProcess: Option<unsafe extern "system" fn(PHANDLE, ACCESS_MASK, PVOID, PVOID) -> NTSTATUS>,
    pub FreeLibrary: Option<unsafe extern "system" fn(HMODULE) -> BOOL>,
    pub GetVolumeInformationW: Option<unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD, PDWORD, PDWORD, PDWORD, LPWSTR, DWORD) -> BOOL>,
    pub GetFileInformationByHandleEx: Option<unsafe extern "system" fn(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD) -> BOOL>,
    pub QueryFullProcessImageNameW: Option<unsafe extern "system" fn(HANDLE, DWORD, LPWSTR, PDWORD) -> BOOL>,
    pub GetLastError: Option<unsafe extern "system" fn() -> DWORD>,
    pub OpenProcess: Option<unsafe extern "system" fn(DWORD, BOOL, DWORD) -> HANDLE>,
    pub CryptMsgGetParam: Option<unsafe extern "system" fn(HCRYPTMSG, DWORD, DWORD, *mut std::ffi::c_void, PDWORD) -> BOOL>,
    pub OpenSCManagerA: Option<unsafe extern "system" fn(LPCSTR, LPCSTR, DWORD) -> SC_HANDLE>,
    pub GetTokenInformation: Option<unsafe extern "system" fn(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD) -> BOOL>,
    pub CertCloseStore: Option<unsafe extern "system" fn(HCERTSTORE, DWORD) -> BOOL>,
    pub WideCharToMultiByte: Option<unsafe extern "system" fn(UINT, DWORD, LPCWCH, i32, LPSTR, i32, LPCCH, *mut BOOL) -> i32>,
    pub GetModuleHandleExA: Option<unsafe extern "system" fn(DWORD, LPCSTR, *mut HMODULE) -> BOOL>,
    pub SetFilePointerEx: Option<unsafe extern "system" fn(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD) -> BOOL>,
    pub FindFirstVolumeW: Option<unsafe extern "system" fn(LPWSTR, DWORD) -> HANDLE>,
    pub Module32FirstW: Option<unsafe extern "system" fn(HANDLE, LPMODULEENTRY32W) -> BOOL>,
    pub CryptMsgClose: Option<unsafe extern "system" fn(HCRYPTMSG) -> BOOL>,
    pub GetFileVersionInfoSizeA: Option<unsafe extern "system" fn(LPCSTR, PDWORD) -> DWORD>,
    pub GetCurrentProcess: Option<unsafe extern "system" fn() -> HANDLE>,
    pub GetModuleInformation: Option<unsafe extern "system" fn(HANDLE, HMODULE, LPMODULEINFO, DWORD) -> BOOL>,
    pub VerQueryValueA: Option<unsafe extern "system" fn(LPCVOID, LPCSTR, *mut LPVOID, *mut UINT) -> BOOL>,
    pub FlushInstructionCache: Option<unsafe extern "system" fn(HANDLE, LPCVOID, SIZE_T) -> BOOL>,
    pub Sleep: Option<unsafe extern "system" fn(DWORD)>,
    pub ResumeThread: Option<unsafe extern "system" fn(HANDLE) -> DWORD>,
    pub WinVerifyTrust: Option<unsafe extern "system" fn(HWND, PGUID, LPVOID) -> LONG>,
    pub GetModuleFileNameExA: Option<unsafe extern "system" fn(HANDLE, HMODULE, LPSTR, DWORD) -> DWORD>,
    pub GetCurrentThread: Option<unsafe extern "system" fn() -> HANDLE>,
    pub GetProcessId: Option<unsafe extern "system" fn(HANDLE) -> DWORD>,
    pub GetFileInformationByHandle: Option<unsafe extern "system" fn(HANDLE, LPBY_HANDLE_FILE_INFORMATION) -> BOOL>,
    pub GetVolumePathNamesForVolumeNameW: Option<unsafe extern "system" fn(LPCWSTR, LPWCH, DWORD, PDWORD) -> BOOL>,
    pub SetupDiGetClassDevsA: Option<unsafe extern "system" fn(LPCGUID, PCSTR, HWND, DWORD) -> HDEVINFO>,
    pub CreateToolhelp32Snapshot: Option<unsafe extern "system" fn(DWORD, DWORD) -> HANDLE>,
    pub ConvertSidToStringSidA: Option<unsafe extern "system" fn(PSID, *mut LPSTR) -> BOOL>,
    pub WriteFile: Option<unsafe extern "system" fn(HANDLE, LPCVOID, DWORD, PDWORD, LPOVERLAPPED) -> BOOL>,
    pub NtWow64QueryVirtualMemory64: Option<unsafe extern "system" fn(HANDLE, PVOID64, DWORD, PVOID, ULONG64, PULONG64) -> NTSTATUS>,
    pub GetModuleBaseNameA: Option<unsafe extern "system" fn(HANDLE, HMODULE, LPSTR, DWORD) -> DWORD>,
    pub RegEnumKeyExA: Option<unsafe extern "system" fn(HKEY, DWORD, LPSTR, PDWORD, PDWORD, LPSTR, PDWORD, PFILETIME) -> LSTATUS>,
    pub CertGetNameStringW: Option<unsafe extern "system" fn(PCCERT_CONTEXT, DWORD, DWORD, *mut std::ffi::c_void, LPWSTR, DWORD) -> DWORD>,
    pub GetSystemDirectoryW: Option<unsafe extern "system" fn(LPWSTR, UINT) -> UINT>,
    pub GetProcessImageFileNameA: Option<unsafe extern "system" fn(HANDLE, LPSTR, DWORD) -> DWORD>,
    pub QueryServiceConfigA: Option<unsafe extern "system" fn(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, PDWORD) -> BOOL>,
    pub GetUserNameExW: Option<unsafe extern "system" fn(EXTENDED_NAME_FORMAT, LPWSTR, PULONG) -> BOOLEAN>,
    pub IsBadReadPtr: Option<unsafe extern "system" fn(LPCVOID, UINT_PTR) -> BOOL>,
    pub CryptQueryObject: Option<unsafe extern "system" fn(DWORD, *const std::ffi::c_void, DWORD, DWORD, DWORD, PDWORD, PDWORD, PDWORD, *mut HCERTSTORE, *mut HCRYPTMSG, *mut *const std::ffi::c_void) -> BOOL>,
    pub GetFileVersionInfoSizeW: Option<unsafe extern "system" fn(LPCWSTR, PDWORD) -> DWORD>,
    pub CloseServiceHandle: Option<unsafe extern "system" fn(SC_HANDLE) -> BOOL>,
    pub RegQueryValueExA: Option<unsafe extern "system" fn(HKEY, LPCSTR, PDWORD, PDWORD, LPBYTE, PDWORD) -> LSTATUS>,
    pub NtQuerySystemInformation: Option<unsafe extern "system" fn(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS>,
    pub GetVolumeInformationByHandleW: Option<unsafe extern "system" fn(HANDLE, LPWSTR, DWORD, PDWORD, PDWORD, PDWORD, LPWSTR, DWORD) -> BOOL>,
    pub EncodePointer: Option<unsafe extern "system" fn(PVOID) -> PVOID>,
    pub OpenThread: Option<unsafe extern "system" fn(DWORD, BOOL, DWORD) -> HANDLE>,
    pub GetFileVersionInfoA: Option<unsafe extern "system" fn(LPCSTR, DWORD, DWORD, LPVOID) -> BOOL>,
    pub QueryServiceConfigW: Option<unsafe extern "system" fn(SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, PDWORD) -> BOOL>,
    pub NtMapViewOfSection: Option<unsafe extern "system" fn(HANDLE, HANDLE, *mut PVOID, ULONG, ULONG, PLARGE_INTEGER, PULONG, DWORD, ULONG, ULONG) -> NTSTATUS>,
    pub ReadFile: Option<unsafe extern "system" fn(HANDLE, LPVOID, DWORD, PDWORD, LPOVERLAPPED) -> BOOL>,
    pub GetProcessTimes: Option<unsafe extern "system" fn(HANDLE, PFILETIME, PFILETIME, PFILETIME, PFILETIME) -> BOOL>,
    pub CertFindCertificateInStore: Option<unsafe extern "system" fn(HCERTSTORE, DWORD, DWORD, DWORD, *const std::ffi::c_void, PCCERT_CONTEXT) -> PCCERT_CONTEXT>,
    pub EnumServicesStatusA: Option<unsafe extern "system" fn(SC_HANDLE, DWORD, DWORD, LPENUM_SERVICE_STATUSA, DWORD, PDWORD, PDWORD, PDWORD) -> BOOL>,
    pub VerQueryValueW: Option<unsafe extern "system" fn(LPCVOID, LPCWSTR, *mut LPVOID, *mut UINT) -> BOOL>,
    pub GetComputerNameExW: Option<unsafe extern "system" fn(COMPUTER_NAME_FORMAT, LPWSTR, PDWORD) -> BOOL>,
    pub GetMappedFileNameW: Option<unsafe extern "system" fn(HANDLE, LPVOID, LPWSTR, DWORD) -> DWORD>,
    pub VirtualQueryEx: Option<unsafe extern "system" fn(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T) -> SIZE_T>,
    pub GetThreadId: Option<unsafe extern "system" fn(HANDLE) -> DWORD>,
    pub GetProcessHeap: Option<unsafe extern "system" fn() -> HANDLE>,
    pub GetModuleBaseNameW: Option<unsafe extern "system" fn(HANDLE, HMODULE, LPWSTR, DWORD) -> DWORD>,
    pub GetModuleFileNameExW: Option<unsafe extern "system" fn(HANDLE, HMODULE, LPWSTR, DWORD) -> DWORD>,
    pub CloseHandle: Option<unsafe extern "system" fn(HANDLE) -> BOOL>,
    pub NtQueryInformationThread: Option<unsafe extern "system" fn(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS>,
    pub OpenProcessToken: Option<unsafe extern "system" fn(HANDLE, DWORD, PHANDLE) -> BOOL>,
    pub MultiByteToWideChar: Option<unsafe extern "system" fn(UINT, DWORD, LPCCH, i32, LPWSTR, i32) -> i32>,
    pub VirtualFreeEx: Option<unsafe extern "system" fn(HANDLE, LPVOID, SIZE_T, DWORD) -> BOOL>,
    pub Module32NextW: Option<unsafe extern "system" fn(HANDLE, LPMODULEENTRY32W) -> BOOL>,
    pub OpenServiceA: Option<unsafe extern "system" fn(SC_HANDLE, LPCSTR, DWORD) -> SC_HANDLE>,
    pub OpenServiceW: Option<unsafe extern "system" fn(SC_HANDLE, LPCWSTR, DWORD) -> SC_HANDLE>,
    pub EnumServicesStatusW: Option<unsafe extern "system" fn(SC_HANDLE, DWORD, DWORD, LPENUM_SERVICE_STATUSW, DWORD, PDWORD, PDWORD, PDWORD) -> BOOL>,
    pub GetFileSizeEx: Option<unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> BOOL>,
    pub LookupPrivilegeValueA: Option<unsafe extern "system" fn(LPCSTR, LPCSTR, *mut std::ffi::c_void) -> BOOL>,
    pub GetThreadContext: Option<unsafe extern "system" fn(HANDLE, LPCONTEXT) -> BOOL>,
    pub GetWindowsDirectoryW: Option<unsafe extern "system" fn(LPWSTR, UINT) -> UINT>,
    pub HeapAlloc: Option<unsafe extern "system" fn(HANDLE, DWORD, SIZE_T) -> LPVOID>,
    pub Heap32First: Option<unsafe extern "system" fn(LPHEAPENTRY32, DWORD, ULONG_PTR) -> BOOL>,
    pub UnmapViewOfFile: Option<unsafe extern "system" fn(LPCVOID) -> BOOL>,
    pub RegCloseKey: Option<unsafe extern "system" fn(HKEY) -> LSTATUS>,
    pub GetUdp6Table: Option<unsafe extern "system" fn(PMIB_UDP6TABLE, PULONG, BOOL) -> ULONG>,
    pub EnumProcessModules: Option<unsafe extern "system" fn(HANDLE, *mut HMODULE, DWORD, PDWORD) -> BOOL>,
    pub MapViewOfFile: Option<unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, SIZE_T) -> LPVOID>,
    pub NtDuplicateObject: Option<unsafe extern "system" fn(HANDLE, PHANDLE, HANDLE, PHANDLE, ACCESS_MASK, BOOLEAN, ULONG) -> NTSTATUS>,
    pub Thread32Next: Option<unsafe extern "system" fn(HANDLE, LPTHREADENTRY32) -> BOOL>,
    pub CreateFileW: Option<unsafe extern "system" fn(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) -> HANDLE>,
    pub StackWalk64: Option<unsafe extern "system" fn(DWORD, HANDLE, HANDLE, LPSTACKFRAME64, PVOID, PREAD_PROCESS_MEMORY_ROUTINE64, PFUNCTION_TABLE_ACCESS_ROUTINE64, PGET_MODULE_BASE_ROUTINE64, PTRANSLATE_ADDRESS_ROUTINE64) -> BOOL>,
    pub HeapFree: Option<unsafe extern "system" fn(HANDLE, DWORD, LPVOID) -> BOOL>,
    pub NtWow64ReadVirtualMemory64: Option<unsafe extern "system" fn(HANDLE, PVOID64, PVOID, ULONG64, PULONG64) -> NTSTATUS>,
    pub GetProcessImageFileNameW: Option<unsafe extern "system" fn(HANDLE, LPWSTR, DWORD) -> DWORD>,
    pub NtOpenSection: Option<unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS>,
    pub CreateFileMappingW: Option<unsafe extern "system" fn(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR) -> HANDLE>,
    pub QueryDosDeviceA: Option<unsafe extern "system" fn(LPCSTR, LPSTR, DWORD) -> DWORD>,
    pub GetVersionExW: Option<unsafe extern "system" fn(LPOSVERSIONINFOEXW) -> BOOL>,
    pub SwitchToThread: Option<unsafe extern "system" fn() -> BOOL>,
    pub WriteProcessMemory: Option<unsafe extern "system" fn(HANDLE, LPVOID, LPCVOID, SIZE_T, *mut SIZE_T) -> BOOL>,
    pub LocalAlloc: Option<unsafe extern "system" fn(UINT, SIZE_T) -> HLOCAL>,
    pub EnumProcesses: Option<unsafe extern "system" fn(PDWORD, DWORD, PDWORD) -> BOOL>,
    pub GetFileVersionInfoW: Option<unsafe extern "system" fn(LPCWSTR, DWORD, DWORD, LPVOID) -> BOOL>,
    pub NtQueryObject: Option<unsafe extern "system" fn(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS>,
    pub NtWow64QueryInformationProcess64: Option<unsafe extern "system" fn(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS>,
    pub QueryDosDeviceW: Option<unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> DWORD>,
    pub WinVerifyTrustEx: Option<unsafe extern "system" fn(HWND, PGUID, PWINTRUST_DATA) -> HRESULT>,
    pub GetCurrentProcessId: Option<unsafe extern "system" fn() -> DWORD>,
    pub GetTcp6Table: Option<unsafe extern "system" fn(PMIB_TCP6TABLE, PULONG, BOOL) -> ULONG>,
    pub SetThreadAffinityMask: Option<unsafe extern "system" fn(HANDLE, DWORD_PTR) -> DWORD_PTR>,
    pub VirtualAlloc: Option<unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID>,
    pub VirtualQuery: Option<unsafe extern "system" fn(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T) -> SIZE_T>,
    pub SetFilePointer: Option<unsafe extern "system" fn(HANDLE, LONG, PLONG, DWORD) -> DWORD>,
    pub Process32FirstW: Option<unsafe extern "system" fn(HANDLE, LPPROCESSENTRY32W) -> BOOL>,
    pub CreateRemoteThread: Option<unsafe extern "system" fn(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, *mut std::ffi::c_void, LPVOID, DWORD, PDWORD) -> HANDLE>,
    pub NtQueryVirtualMemory: Option<unsafe extern "system" fn(HANDLE, PVOID, DWORD, PVOID, ULONG, PULONG) -> NTSTATUS>,
    pub SuspendThread: Option<unsafe extern "system" fn(HANDLE) -> DWORD>,
    pub CryptDecodeObject: Option<unsafe extern "system" fn(DWORD, LPCSTR, *const u8, DWORD, DWORD, *mut std::ffi::c_void, PDWORD) -> BOOL>,
    pub NtQueryInformationProcess: Option<unsafe extern "system" fn(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS>,
    pub LoadLibraryA: Option<unsafe extern "system" fn(LPCSTR) -> HMODULE>,
    pub SetupDiGetDeviceRegistryPropertyA: Option<unsafe extern "system" fn(HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, *mut u8, DWORD, PDWORD) -> BOOL>,
    pub FindVolumeClose: Option<unsafe extern "system" fn(HANDLE) -> BOOL>,
    pub NtReadVirtualMemory: Option<unsafe extern "system" fn(HANDLE, PVOID, PVOID, ULONG, PULONG) -> NTSTATUS>,
    pub IsWow64Process: Option<unsafe extern "system" fn(HANDLE, PBOOL) -> BOOL>,
    pub GetModuleHandleA: Option<unsafe extern "system" fn(LPCSTR) -> HMODULE>,
    pub GetDriveTypeW: Option<unsafe extern "system" fn(LPCWSTR) -> UINT>,
    pub RegQueryInfoKeyA: Option<unsafe extern "system" fn(HKEY, LPSTR, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PFILETIME) -> LSTATUS>,
    pub AdjustTokenPrivileges: Option<unsafe extern "system" fn(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD) -> BOOL>,
    pub Thread32First: Option<unsafe extern "system" fn(HANDLE, LPTHREADENTRY32) -> BOOL>,
    pub GetVersionExA: Option<unsafe extern "system" fn(LPOSVERSIONINFOEXA) -> BOOL>,
    pub FindNextVolumeW: Option<unsafe extern "system" fn(HANDLE, LPWSTR, DWORD) -> BOOL>,
    pub GetCurrentThreadId: Option<unsafe extern "system" fn() -> DWORD>,
    pub NtQueryDirectoryObject: Option<unsafe extern "system" fn(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG) -> NTSTATUS>,
    pub RtlGetCompressionWorkSpaceSize: Option<unsafe extern "system" fn(ULONG, PULONG, PULONG) -> NTSTATUS>,
    pub GetSystemDirectoryA: Option<unsafe extern "system" fn(LPSTR, UINT) -> UINT>,
    pub SetupDiDestroyDeviceInfoList: Option<unsafe extern "system" fn(HDEVINFO) -> BOOL>,
    pub GetUserProfileDirectoryA: Option<unsafe extern "system" fn(HANDLE, LPSTR, PDWORD) -> BOOL>,
    pub GetTickCount: Option<unsafe extern "system" fn() -> DWORD>,
    pub ReadProcessMemory: Option<unsafe extern "system" fn(HANDLE, LPCVOID, LPVOID, SIZE_T, *mut SIZE_T) -> BOOL>,
    pub VirtualFree: Option<unsafe extern "system" fn(LPVOID, SIZE_T, DWORD) -> BOOL>,
    pub CryptHashCertificate: Option<unsafe extern "system" fn(HCRYPTPROV_LEGACY, ALG_ID, DWORD, *const u8, DWORD, *mut u8, PDWORD) -> BOOL>,
    pub VirtualAllocEx: Option<unsafe extern "system" fn(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID>,
    pub NtClose: Option<unsafe extern "system" fn(HANDLE) -> NTSTATUS>,
    pub Process32NextW: Option<unsafe extern "system" fn(HANDLE, LPPROCESSENTRY32W) -> BOOL>,
    pub CertFreeCertificateContext: Option<unsafe extern "system" fn(PCCERT_CONTEXT) -> BOOL>,
    pub NtOpenDirectoryObject: Option<unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS>,
    pub GetSystemTimeAsFileTime: Option<unsafe extern "system" fn(PFILETIME)>,
    pub OutputDebugStringA: Option<unsafe extern "system" fn(LPCSTR)>,
    pub GetUserProfileDirectoryW: Option<unsafe extern "system" fn(HANDLE, LPWSTR, PDWORD) -> BOOL>,
    pub AddVectoredExceptionHandler: Option<unsafe extern "system" fn(ULONG, PVECTORED_EXCEPTION_HANDLER) -> PVOID>,
    pub GetSystemInfo: Option<unsafe extern "system" fn(LPSYSTEM_INFO)>,
    pub GetModuleFileNameA: Option<unsafe extern "system" fn(HMODULE, LPSTR, DWORD) -> DWORD>,
    pub WaitForSingleObject: Option<unsafe extern "system" fn(HANDLE, DWORD) -> DWORD>,
    pub SymFunctionTableAccess64: Option<unsafe extern "system" fn(HANDLE, DWORD64) -> PVOID>,
    pub SetupDiEnumDeviceInfo: Option<unsafe extern "system" fn(HDEVINFO, DWORD, PSP_DEVINFO_DATA) -> BOOL>,
    pub DeviceIoControl: Option<unsafe extern "system" fn(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, PDWORD, LPOVERLAPPED) -> BOOL>,
    pub SetLastError: Option<unsafe extern "system" fn(DWORD)>,
    pub GetUdpTable: Option<unsafe extern "system" fn(PMIB_UDPTABLE, PULONG, BOOL) -> ULONG>,
    pub LocalFree: Option<unsafe extern "system" fn(HLOCAL) -> HLOCAL>,
    pub RegOpenKeyExA: Option<unsafe extern "system" fn(HKEY, LPCSTR, DWORD, REGSAM, PHKEY) -> LSTATUS>,
    pub NtQuerySection: Option<unsafe extern "system" fn(HANDLE, DWORD, PVOID, ULONG, PULONG) -> NTSTATUS>,
    pub SymGetModuleBase64: Option<unsafe extern "system" fn(HANDLE, DWORD64) -> DWORD64>,
    pub GetFileSize: Option<unsafe extern "system" fn(HANDLE, PDWORD) -> DWORD>,
    pub RtlDecompressBufferEx: Option<unsafe extern "system" fn(u16, *mut u8, ULONG, *const u8, ULONG, PULONG, PVOID) -> NTSTATUS>,
    pub VirtualProtect: Option<unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, PDWORD) -> BOOL>,
    pub GetLogicalDriveStringsA: Option<unsafe extern "system" fn(DWORD, LPSTR) -> DWORD>,
    pub OpenFileById: Option<unsafe extern "system" fn(HANDLE, LPFILE_ID_DESCRIPTOR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD) -> HANDLE>,
    pub GetLogicalDriveStringsW: Option<unsafe extern "system" fn(DWORD, LPWSTR) -> DWORD>,
    pub CreateFileA: Option<unsafe extern "system" fn(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) -> HANDLE>,
    pub GetTcpTable: Option<unsafe extern "system" fn(PMIB_TCPTABLE, PULONG, BOOL) -> ULONG>,
    pub GetWindowsDirectoryA: Option<unsafe extern "system" fn(LPSTR, UINT) -> UINT>,
    pub GetMappedFileNameA: Option<unsafe extern "system" fn(HANDLE, LPVOID, LPSTR, DWORD) -> DWORD>,
    pub pad: [DWORD; 28],
}

impl WinApiTable {
    pub fn empty() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

// Direct Win32 FFI declarations needed for bootstrapping the table
#[cfg(target_os = "windows")]
extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> HMODULE;
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> FARPROC;
    fn LoadLibraryA(lpLibFileName: *const u8) -> HMODULE;
}

#[cfg(target_os = "windows")]
macro_rules! resolve {
    ($table:expr, $field:ident, $dll:expr, $name:expr) => {
        unsafe {
            let handle = if $dll == "kernel32.dll" || $dll == "kernelbase.dll" {
                GetModuleHandleA(concat!($dll, "\0").as_ptr() as *const u8)
            } else if $dll == "ntdll.dll" {
                GetModuleHandleA(concat!($dll, "\0").as_ptr() as *const u8)
            } else {
                let h = GetModuleHandleA(concat!($dll, "\0").as_ptr() as *const u8);
                if h.is_null() {
                    LoadLibraryA(concat!($dll, "\0").as_ptr() as *const u8)
                } else {
                    h
                }
            };
            if !handle.is_null() {
                let addr = GetProcAddress(handle, concat!($name, "\0").as_ptr() as *const u8);
                $table.$field = std::mem::transmute(addr);
            }
        }
    };
}

#[cfg(target_os = "windows")]
pub fn resolve_winapi() -> WinApiTable {
    let mut t: WinApiTable = WinApiTable::empty();

    resolve!(t, LoadLibraryExA, "kernel32.dll", "LoadLibraryExA");
    resolve!(t, GetProcAddress, "kernel32.dll", "GetProcAddress");
    resolve!(t, NtOpenProcess, "ntdll.dll", "NtOpenProcess");
    resolve!(t, FreeLibrary, "kernel32.dll", "FreeLibrary");
    resolve!(t, GetVolumeInformationW, "kernel32.dll", "GetVolumeInformationW");
    resolve!(t, GetFileInformationByHandleEx, "kernel32.dll", "GetFileInformationByHandleEx");
    resolve!(t, QueryFullProcessImageNameW, "kernel32.dll", "QueryFullProcessImageNameW");
    resolve!(t, GetLastError, "kernel32.dll", "GetLastError");
    resolve!(t, OpenProcess, "kernel32.dll", "OpenProcess");
    resolve!(t, CryptMsgGetParam, "crypt32.dll", "CryptMsgGetParam");
    resolve!(t, OpenSCManagerA, "advapi32.dll", "OpenSCManagerA");
    resolve!(t, GetTokenInformation, "advapi32.dll", "GetTokenInformation");
    resolve!(t, CertCloseStore, "crypt32.dll", "CertCloseStore");
    resolve!(t, WideCharToMultiByte, "kernel32.dll", "WideCharToMultiByte");
    resolve!(t, GetModuleHandleExA, "kernel32.dll", "GetModuleHandleExA");
    resolve!(t, SetFilePointerEx, "kernel32.dll", "SetFilePointerEx");
    resolve!(t, FindFirstVolumeW, "kernel32.dll", "FindFirstVolumeW");
    resolve!(t, Module32FirstW, "kernel32.dll", "Module32FirstW");
    resolve!(t, CryptMsgClose, "crypt32.dll", "CryptMsgClose");
    resolve!(t, GetFileVersionInfoSizeA, "version.dll", "GetFileVersionInfoSizeA");
    resolve!(t, GetCurrentProcess, "kernel32.dll", "GetCurrentProcess");
    resolve!(t, GetModuleInformation, "kernel32.dll", "GetModuleInformation");
    resolve!(t, VerQueryValueA, "version.dll", "VerQueryValueA");
    resolve!(t, FlushInstructionCache, "kernel32.dll", "FlushInstructionCache");
    resolve!(t, Sleep, "kernel32.dll", "Sleep");
    resolve!(t, ResumeThread, "kernel32.dll", "ResumeThread");
    resolve!(t, WinVerifyTrust, "wintrust.dll", "WinVerifyTrust");
    resolve!(t, GetModuleFileNameExA, "kernel32.dll", "GetModuleFileNameExA");
    resolve!(t, GetCurrentThread, "kernel32.dll", "GetCurrentThread");
    resolve!(t, GetProcessId, "kernel32.dll", "GetProcessId");
    resolve!(t, GetFileInformationByHandle, "kernel32.dll", "GetFileInformationByHandle");
    resolve!(t, GetVolumePathNamesForVolumeNameW, "kernel32.dll", "GetVolumePathNamesForVolumeNameW");
    resolve!(t, SetupDiGetClassDevsA, "setupapi.dll", "SetupDiGetClassDevsA");
    resolve!(t, CreateToolhelp32Snapshot, "kernel32.dll", "CreateToolhelp32Snapshot");
    resolve!(t, ConvertSidToStringSidA, "advapi32.dll", "ConvertSidToStringSidA");
    resolve!(t, WriteFile, "kernel32.dll", "WriteFile");
    resolve!(t, NtWow64QueryVirtualMemory64, "ntdll.dll", "NtWow64QueryVirtualMemory64");
    resolve!(t, GetModuleBaseNameA, "kernel32.dll", "GetModuleBaseNameA");
    resolve!(t, RegEnumKeyExA, "advapi32.dll", "RegEnumKeyExA");
    resolve!(t, CertGetNameStringW, "crypt32.dll", "CertGetNameStringW");
    resolve!(t, GetSystemDirectoryW, "kernel32.dll", "GetSystemDirectoryW");
    resolve!(t, GetProcessImageFileNameA, "kernel32.dll", "GetProcessImageFileNameA");
    resolve!(t, QueryServiceConfigA, "advapi32.dll", "QueryServiceConfigA");
    resolve!(t, GetUserNameExW, "secur32.dll", "GetUserNameExW");
    resolve!(t, IsBadReadPtr, "kernel32.dll", "IsBadReadPtr");
    resolve!(t, CryptQueryObject, "crypt32.dll", "CryptQueryObject");
    resolve!(t, GetFileVersionInfoSizeW, "version.dll", "GetFileVersionInfoSizeW");
    resolve!(t, CloseServiceHandle, "advapi32.dll", "CloseServiceHandle");
    resolve!(t, RegQueryValueExA, "advapi32.dll", "RegQueryValueExA");
    resolve!(t, NtQuerySystemInformation, "ntdll.dll", "NtQuerySystemInformation");
    resolve!(t, GetVolumeInformationByHandleW, "kernel32.dll", "GetVolumeInformationByHandleW");
    resolve!(t, EncodePointer, "kernel32.dll", "EncodePointer");
    resolve!(t, OpenThread, "kernel32.dll", "OpenThread");
    resolve!(t, GetFileVersionInfoA, "version.dll", "GetFileVersionInfoA");
    resolve!(t, QueryServiceConfigW, "advapi32.dll", "QueryServiceConfigW");
    resolve!(t, NtMapViewOfSection, "ntdll.dll", "NtMapViewOfSection");
    resolve!(t, ReadFile, "kernel32.dll", "ReadFile");
    resolve!(t, GetProcessTimes, "kernel32.dll", "GetProcessTimes");
    resolve!(t, CertFindCertificateInStore, "crypt32.dll", "CertFindCertificateInStore");
    resolve!(t, EnumServicesStatusA, "advapi32.dll", "EnumServicesStatusA");
    resolve!(t, VerQueryValueW, "version.dll", "VerQueryValueW");
    resolve!(t, GetComputerNameExW, "kernel32.dll", "GetComputerNameExW");
    resolve!(t, GetMappedFileNameW, "kernel32.dll", "GetMappedFileNameW");
    resolve!(t, VirtualQueryEx, "kernel32.dll", "VirtualQueryEx");
    resolve!(t, GetThreadId, "kernel32.dll", "GetThreadId");
    resolve!(t, GetProcessHeap, "kernel32.dll", "GetProcessHeap");
    resolve!(t, GetModuleBaseNameW, "kernel32.dll", "GetModuleBaseNameW");
    resolve!(t, GetModuleFileNameExW, "kernel32.dll", "GetModuleFileNameExW");
    resolve!(t, CloseHandle, "kernel32.dll", "CloseHandle");
    resolve!(t, NtQueryInformationThread, "ntdll.dll", "NtQueryInformationThread");
    resolve!(t, OpenProcessToken, "advapi32.dll", "OpenProcessToken");
    resolve!(t, MultiByteToWideChar, "kernel32.dll", "MultiByteToWideChar");
    resolve!(t, VirtualFreeEx, "kernel32.dll", "VirtualFreeEx");
    resolve!(t, Module32NextW, "kernel32.dll", "Module32NextW");
    resolve!(t, OpenServiceA, "advapi32.dll", "OpenServiceA");
    resolve!(t, OpenServiceW, "advapi32.dll", "OpenServiceW");
    resolve!(t, EnumServicesStatusW, "advapi32.dll", "EnumServicesStatusW");
    resolve!(t, GetFileSizeEx, "kernel32.dll", "GetFileSizeEx");
    resolve!(t, LookupPrivilegeValueA, "advapi32.dll", "LookupPrivilegeValueA");
    resolve!(t, GetThreadContext, "kernel32.dll", "GetThreadContext");
    resolve!(t, GetWindowsDirectoryW, "kernel32.dll", "GetWindowsDirectoryW");
    resolve!(t, HeapAlloc, "kernel32.dll", "HeapAlloc");
    resolve!(t, Heap32First, "kernel32.dll", "Heap32First");
    resolve!(t, UnmapViewOfFile, "kernel32.dll", "UnmapViewOfFile");
    resolve!(t, RegCloseKey, "advapi32.dll", "RegCloseKey");
    resolve!(t, GetUdp6Table, "iphlpapi.dll", "GetUdp6Table");
    resolve!(t, EnumProcessModules, "psapi.dll", "EnumProcessModules");
    resolve!(t, MapViewOfFile, "kernel32.dll", "MapViewOfFile");
    resolve!(t, NtDuplicateObject, "ntdll.dll", "NtDuplicateObject");
    resolve!(t, Thread32Next, "kernel32.dll", "Thread32Next");
    resolve!(t, CreateFileW, "kernel32.dll", "CreateFileW");
    resolve!(t, StackWalk64, "kernel32.dll", "StackWalk64");
    resolve!(t, HeapFree, "kernel32.dll", "HeapFree");
    resolve!(t, NtWow64ReadVirtualMemory64, "ntdll.dll", "NtWow64ReadVirtualMemory64");
    resolve!(t, GetProcessImageFileNameW, "kernel32.dll", "GetProcessImageFileNameW");
    resolve!(t, NtOpenSection, "ntdll.dll", "NtOpenSection");
    resolve!(t, CreateFileMappingW, "kernel32.dll", "CreateFileMappingW");
    resolve!(t, QueryDosDeviceA, "kernel32.dll", "QueryDosDeviceA");
    resolve!(t, GetVersionExW, "kernel32.dll", "GetVersionExW");
    resolve!(t, SwitchToThread, "kernel32.dll", "SwitchToThread");
    resolve!(t, WriteProcessMemory, "kernel32.dll", "WriteProcessMemory");
    resolve!(t, LocalAlloc, "kernel32.dll", "LocalAlloc");
    resolve!(t, EnumProcesses, "kernel32.dll", "EnumProcesses");
    resolve!(t, GetFileVersionInfoW, "version.dll", "GetFileVersionInfoW");
    resolve!(t, NtQueryObject, "ntdll.dll", "NtQueryObject");
    resolve!(t, NtWow64QueryInformationProcess64, "ntdll.dll", "NtWow64QueryInformationProcess64");
    resolve!(t, QueryDosDeviceW, "kernel32.dll", "QueryDosDeviceW");
    resolve!(t, WinVerifyTrustEx, "wintrust.dll", "WinVerifyTrustEx");
    resolve!(t, GetCurrentProcessId, "kernel32.dll", "GetCurrentProcessId");
    resolve!(t, GetTcp6Table, "iphlpapi.dll", "GetTcp6Table");
    resolve!(t, SetThreadAffinityMask, "kernel32.dll", "SetThreadAffinityMask");
    resolve!(t, VirtualAlloc, "kernel32.dll", "VirtualAlloc");
    resolve!(t, VirtualQuery, "kernel32.dll", "VirtualQuery");
    resolve!(t, SetFilePointer, "kernel32.dll", "SetFilePointer");
    resolve!(t, Process32FirstW, "kernel32.dll", "Process32FirstW");
    resolve!(t, CreateRemoteThread, "kernel32.dll", "CreateRemoteThread");
    resolve!(t, NtQueryVirtualMemory, "ntdll.dll", "NtQueryVirtualMemory");
    resolve!(t, SuspendThread, "kernel32.dll", "SuspendThread");
    resolve!(t, CryptDecodeObject, "crypt32.dll", "CryptDecodeObject");
    resolve!(t, NtQueryInformationProcess, "ntdll.dll", "NtQueryInformationProcess");
    resolve!(t, LoadLibraryA, "kernel32.dll", "LoadLibraryA");
    resolve!(t, SetupDiGetDeviceRegistryPropertyA, "setupapi.dll", "SetupDiGetDeviceRegistryPropertyA");
    resolve!(t, FindVolumeClose, "kernel32.dll", "FindVolumeClose");
    resolve!(t, NtReadVirtualMemory, "ntdll.dll", "NtReadVirtualMemory");
    resolve!(t, IsWow64Process, "kernel32.dll", "IsWow64Process");
    resolve!(t, GetModuleHandleA, "kernel32.dll", "GetModuleHandleA");
    resolve!(t, GetDriveTypeW, "kernel32.dll", "GetDriveTypeW");
    resolve!(t, RegQueryInfoKeyA, "advapi32.dll", "RegQueryInfoKeyA");
    resolve!(t, AdjustTokenPrivileges, "advapi32.dll", "AdjustTokenPrivileges");
    resolve!(t, Thread32First, "kernel32.dll", "Thread32First");
    resolve!(t, GetVersionExA, "kernel32.dll", "GetVersionExA");
    resolve!(t, FindNextVolumeW, "kernel32.dll", "FindNextVolumeW");
    resolve!(t, GetCurrentThreadId, "kernel32.dll", "GetCurrentThreadId");
    resolve!(t, NtQueryDirectoryObject, "ntdll.dll", "NtQueryDirectoryObject");
    resolve!(t, RtlGetCompressionWorkSpaceSize, "ntdll.dll", "RtlGetCompressionWorkSpaceSize");
    resolve!(t, GetSystemDirectoryA, "kernel32.dll", "GetSystemDirectoryA");
    resolve!(t, SetupDiDestroyDeviceInfoList, "setupapi.dll", "SetupDiDestroyDeviceInfoList");
    resolve!(t, GetUserProfileDirectoryA, "kernel32.dll", "GetUserProfileDirectoryA");
    resolve!(t, GetTickCount, "kernel32.dll", "GetTickCount");
    resolve!(t, ReadProcessMemory, "kernel32.dll", "ReadProcessMemory");
    resolve!(t, VirtualFree, "kernel32.dll", "VirtualFree");
    resolve!(t, CryptHashCertificate, "crypt32.dll", "CryptHashCertificate");
    resolve!(t, VirtualAllocEx, "kernel32.dll", "VirtualAllocEx");
    resolve!(t, NtClose, "ntdll.dll", "NtClose");
    resolve!(t, Process32NextW, "kernel32.dll", "Process32NextW");
    resolve!(t, CertFreeCertificateContext, "crypt32.dll", "CertFreeCertificateContext");
    resolve!(t, NtOpenDirectoryObject, "ntdll.dll", "NtOpenDirectoryObject");
    resolve!(t, GetSystemTimeAsFileTime, "kernel32.dll", "GetSystemTimeAsFileTime");
    resolve!(t, OutputDebugStringA, "kernel32.dll", "OutputDebugStringA");
    resolve!(t, GetUserProfileDirectoryW, "kernel32.dll", "GetUserProfileDirectoryW");
    resolve!(t, AddVectoredExceptionHandler, "kernel32.dll", "AddVectoredExceptionHandler");
    resolve!(t, GetSystemInfo, "kernel32.dll", "GetSystemInfo");
    resolve!(t, GetModuleFileNameA, "kernel32.dll", "GetModuleFileNameA");
    resolve!(t, WaitForSingleObject, "kernel32.dll", "WaitForSingleObject");
    resolve!(t, SymFunctionTableAccess64, "kernel32.dll", "SymFunctionTableAccess64");
    resolve!(t, SetupDiEnumDeviceInfo, "setupapi.dll", "SetupDiEnumDeviceInfo");
    resolve!(t, DeviceIoControl, "kernel32.dll", "DeviceIoControl");
    resolve!(t, SetLastError, "kernel32.dll", "SetLastError");
    resolve!(t, GetUdpTable, "iphlpapi.dll", "GetUdpTable");
    resolve!(t, LocalFree, "kernel32.dll", "LocalFree");
    resolve!(t, RegOpenKeyExA, "advapi32.dll", "RegOpenKeyExA");
    resolve!(t, NtQuerySection, "ntdll.dll", "NtQuerySection");
    resolve!(t, SymGetModuleBase64, "kernel32.dll", "SymGetModuleBase64");
    resolve!(t, GetFileSize, "kernel32.dll", "GetFileSize");
    resolve!(t, RtlDecompressBufferEx, "ntdll.dll", "RtlDecompressBufferEx");
    resolve!(t, VirtualProtect, "kernel32.dll", "VirtualProtect");
    resolve!(t, GetLogicalDriveStringsA, "kernel32.dll", "GetLogicalDriveStringsA");
    resolve!(t, OpenFileById, "kernel32.dll", "OpenFileById");
    resolve!(t, GetLogicalDriveStringsW, "kernel32.dll", "GetLogicalDriveStringsW");
    resolve!(t, CreateFileA, "kernel32.dll", "CreateFileA");
    resolve!(t, GetTcpTable, "iphlpapi.dll", "GetTcpTable");
    resolve!(t, GetWindowsDirectoryA, "kernel32.dll", "GetWindowsDirectoryA");
    resolve!(t, GetMappedFileNameA, "kernel32.dll", "GetMappedFileNameA");

    t
}
