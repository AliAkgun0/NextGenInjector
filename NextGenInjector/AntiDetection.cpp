#include "AntiDetection.h"
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <Wbemidl.h>
#include <comdef.h>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <algorithm>
#include <iphlpapi.h>
#include <tchar.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Psapi.lib")

// NtQueryInformationProcess function pointer
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// NtQuerySystemInformation function pointer
typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

AntiDetection::AntiDetection() : gen(rd()), dis(0, 25) {
    InitializeRNG();
}

AntiDetection::~AntiDetection() {
    ClearMemoryTraces();
}

bool AntiDetection::Initialize() {
    if (IsDebuggerPresent() || IsVirtualMachine() || IsSandbox()) {
        return false;
    }
    return true;
}

bool AntiDetection::IsDebuggerPresent() {
    return CheckIsDebuggerPresent() ||
           CheckNtGlobalFlag() ||
           CheckHeapFlags() ||
           CheckProcessDebugFlags() ||
           CheckProcessDebugObject() ||
           CheckSystemDebugger() ||
           CheckHardwareBreakpoints() ||
           CheckSoftwareBreakpoints();
}

bool AntiDetection::IsVirtualMachine() {
    return CheckCPUID() ||
           CheckRegistry() ||
           CheckDrivers() ||
           CheckProcesses() ||
           CheckMACAddress() ||
           CheckBIOS() ||
           CheckDiskSize() ||
           CheckMemorySize();
}

bool AntiDetection::IsSandbox() {
    return CheckUserNames() ||
           CheckSystemInfo() ||
           CheckNetworkInfo() ||
           CheckInstalledSoftware() ||
           CheckRunningProcesses() ||
           CheckFileSystem() ||
           CheckRegistryKeys() ||
           CheckSystemTime();
}

bool AntiDetection::IsBeingDebugged() {
    return IsDebuggerPresent() || IsDebuggerPresent();
}

void AntiDetection::RandomizeWindowTitle(HWND hwnd) {
    if (!hwnd) return;
    std::wstring title = GenerateRandomString(16);
    SetWindowText(hwnd, title.c_str());
}

void AntiDetection::RandomizeWindowClass(HWND hwnd) {
    if (!hwnd) return;
    std::wstring className = GenerateRandomString(16);
    SetClassLongPtr(hwnd, GCLP_HICON, (LONG_PTR)LoadIcon(nullptr, IDI_APPLICATION));
    SetClassLongPtr(hwnd, GCLP_HICONSM, (LONG_PTR)LoadIcon(nullptr, IDI_APPLICATION));
}

void AntiDetection::ClearMemoryTraces() {
    for (auto& str : m_encryptedStrings) {
        SecureZeroMemory(str.data.data(), str.data.size());
    }
    m_encryptedStrings.clear();
}

void AntiDetection::EncryptStrings() {
    // TODO: Implement string encryption
}

void AntiDetection::DecryptStrings() {
    // TODO: Implement string decryption
}

bool AntiDetection::CheckIsDebuggerPresent() {
    return ::IsDebuggerPresent() != FALSE;
}

bool AntiDetection::CheckNtGlobalFlag() {
    PPEB_LITE pPeb = (PPEB_LITE)__readgsqword(0x60);
    return (pPeb->BeingDebugged != 0);
}

bool AntiDetection::CheckHeapFlags() {
    HANDLE hHeap = GetProcessHeap();
    if (!hHeap) return false;

    ULONG flags = 0;
    ULONG forceFlags = 0;
    if (HeapQueryInformation(hHeap, HeapCompatibilityInformation, &flags, sizeof(flags), nullptr)) {
        return (flags & HEAP_NO_SERIALIZE) != 0;
    }
    return false;
}

bool AntiDetection::CheckProcessDebugFlags() {
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        CUSTOM_PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    pNtQueryInformationProcess NtQueryInformationProcess = 
        (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (NtQueryInformationProcess) {
        DWORD ProcessDebugFlags = 0;
        NTSTATUS status = NtQueryInformationProcess(
            GetCurrentProcess(),
            CustomProcessDebugFlags,
            &ProcessDebugFlags,
            sizeof(ProcessDebugFlags),
            nullptr
        );

        if (NT_SUCCESS(status) && ProcessDebugFlags == 0) {
            return true;
        }
    }
    return false;
}

bool AntiDetection::CheckProcessDebugObject() {
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        CUSTOM_PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    pNtQueryInformationProcess NtQueryInformationProcess = 
        (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (NtQueryInformationProcess) {
        HANDLE hDebugObject = nullptr;
        NTSTATUS status = NtQueryInformationProcess(
            GetCurrentProcess(),
            CustomProcessDebugObjectHandle,
            &hDebugObject,
            sizeof(hDebugObject),
            nullptr
        );

        if (NT_SUCCESS(status) && hDebugObject != nullptr) {
            CloseHandle(hDebugObject);
            return true;
        }
    }
    return false;
}

bool AntiDetection::CheckSystemDebugger() {
    typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
        CUSTOM_SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );

    pNtQuerySystemInformation NtQuerySystemInformation = 
        (pNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    if (NtQuerySystemInformation) {
        SYSTEM_KERNEL_DEBUGGER_INFORMATION DebuggerInfo = { 0 };
        NTSTATUS status = NtQuerySystemInformation(
            CustomSystemKernelDebuggerInformation,
            &DebuggerInfo,
            sizeof(DebuggerInfo),
            nullptr
        );

        if (NT_SUCCESS(status) && (DebuggerInfo.KernelDebuggerEnabled || !DebuggerInfo.KernelDebuggerNotPresent)) {
            return true;
        }
    }
    return false;
}

bool AntiDetection::CheckHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        return false;
    }

    return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
}

bool AntiDetection::CheckSoftwareBreakpoints() {
    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) return false;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            BYTE* code = (BYTE*)hModule + pSectionHeader[i].VirtualAddress;
            DWORD size = pSectionHeader[i].SizeOfRawData;

            for (DWORD j = 0; j < size; j++) {
                if (code[j] == 0xCC) { // INT 3
                    return true;
                }
            }
        }
    }

    return false;
}

bool AntiDetection::CheckCPUID() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    return ((cpuInfo[2] >> 31) & 1) != 0;
}

bool AntiDetection::CheckRegistry() {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

bool AntiDetection::CheckDrivers() {
    LPVOID drivers[1024];
    DWORD cbNeeded;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        for (DWORD i = 0; i < cbNeeded / sizeof(LPVOID); i++) {
            TCHAR szDriver[1024];
            if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(TCHAR))) {
                if (_tcsicmp(szDriver, _T("VBoxMouse.sys")) == 0 ||
                    _tcsicmp(szDriver, _T("VBoxGuest.sys")) == 0 ||
                    _tcsicmp(szDriver, _T("VMM.sys")) == 0 ||
                    _tcsicmp(szDriver, _T("VBoxSF.sys")) == 0) {
                    return true;
                }
            }
        }
    }
    return false;
}

bool AntiDetection::CheckProcesses() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"VBoxService.exe") == 0 ||
                _wcsicmp(pe32.szExeFile, L"VBoxTray.exe") == 0 ||
                _wcsicmp(pe32.szExeFile, L"VMTools.exe") == 0 ||
                _wcsicmp(pe32.szExeFile, L"VMwareTray.exe") == 0) {
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return false;
}

bool AntiDetection::CheckMACAddress() {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);

    if (GetAdaptersInfo(adapterInfo, &dwBufLen) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
        while (pAdapterInfo) {
            if (pAdapterInfo->AddressLength == 6) {
                BYTE mac[6];
                memcpy(mac, pAdapterInfo->Address, 6);
                if (mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) { // VMware
                    return true;
                }
                if (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x42) { // VirtualBox
                    return true;
                }
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }
    return false;
}

bool AntiDetection::CheckBIOS() {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        TCHAR szValue[256];
        DWORD dwSize = sizeof(szValue);
        if (RegQueryValueEx(hKey, _T("SystemManufacturer"), nullptr, nullptr, (LPBYTE)szValue, &dwSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return (_tcsicmp(szValue, _T("VMware, Inc.")) == 0 ||
                    _tcsicmp(szValue, _T("innotek GmbH")) == 0 ||
                    _tcsicmp(szValue, _T("Oracle Corporation")) == 0);
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool AntiDetection::CheckDiskSize() {
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
    if (GetDiskFreeSpaceEx(L"C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
        return (totalNumberOfBytes.QuadPart < 100 * 1024 * 1024 * 1024); // Less than 100GB
    }
    return false;
}

bool AntiDetection::CheckMemorySize() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        return (memInfo.ullTotalPhys < 4 * 1024 * 1024 * 1024); // Less than 4GB
    }
    return false;
}

bool AntiDetection::CheckUserNames() {
    TCHAR username[UNLEN + 1];
    DWORD usernameLen = UNLEN + 1;
    if (GetUserName(username, &usernameLen)) {
        return (_tcsicmp(username, _T("sandbox")) == 0 ||
                _tcsicmp(username, _T("malware")) == 0 ||
                _tcsicmp(username, _T("virus")) == 0);
    }
    return false;
}

bool AntiDetection::CheckSystemInfo() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return (sysInfo.dwNumberOfProcessors < 2);
}

bool AntiDetection::CheckNetworkInfo() {
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);

    if (GetAdaptersInfo(pAdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
    }

    if (GetAdaptersInfo(pAdapterInfo, &dwBufLen) == ERROR_SUCCESS) {
        while (pAdapterInfo) {
            if (pAdapterInfo->Type == MIB_IF_TYPE_ETHERNET) {
                if (pAdapterInfo->AddressLength == 6) {
                    BYTE mac[6];
                    memcpy(mac, pAdapterInfo->Address, 6);
                    if (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) { // VMware
                        free(pAdapterInfo);
                        return true;
                    }
                }
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }

    free(pAdapterInfo);
    return false;
}

bool AntiDetection::CheckInstalledSoftware() {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        TCHAR szSubKey[256];
        DWORD dwIndex = 0;
        DWORD dwSize = sizeof(szSubKey);

        while (RegEnumKeyEx(hKey, dwIndex, szSubKey, &dwSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            HKEY hSubKey;
            if (RegOpenKeyEx(hKey, szSubKey, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                TCHAR szValue[256];
                DWORD dwValueSize = sizeof(szValue);
                if (RegQueryValueEx(hSubKey, _T("DisplayName"), nullptr, nullptr, (LPBYTE)szValue, &dwValueSize) == ERROR_SUCCESS) {
                    if (_tcsstr(szValue, _T("VMware")) != nullptr ||
                        _tcsstr(szValue, _T("VirtualBox")) != nullptr ||
                        _tcsstr(szValue, _T("Sandbox")) != nullptr) {
                        RegCloseKey(hSubKey);
                        RegCloseKey(hKey);
                        return true;
                    }
                }
                RegCloseKey(hSubKey);
            }
            dwIndex++;
            dwSize = sizeof(szSubKey);
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool AntiDetection::CheckRunningProcesses() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"vmtoolsd.exe") == 0 ||
                _wcsicmp(pe32.szExeFile, L"vboxservice.exe") == 0 ||
                _wcsicmp(pe32.szExeFile, L"vboxtray.exe") == 0 ||
                _wcsicmp(pe32.szExeFile, L"vmusrvc.exe") == 0) {
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return false;
}

bool AntiDetection::CheckFileSystem() {
    WIN32_FIND_DATA findData;
    HANDLE hFind = FindFirstFile(L"C:\\Program Files\\VMware\\*", &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
        return true;
    }

    hFind = FindFirstFile(L"C:\\Program Files\\Oracle\\VirtualBox\\*", &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
        return true;
    }

    return false;
}

bool AntiDetection::CheckRegistryKeys() {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        TCHAR szValue[256];
        DWORD dwSize = sizeof(szValue);
        if (RegQueryValueEx(hKey, _T("0"), nullptr, nullptr, (LPBYTE)szValue, &dwSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return (_tcsstr(szValue, _T("VMware")) != nullptr ||
                    _tcsstr(szValue, _T("VBOX")) != nullptr);
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool AntiDetection::CheckSystemTime() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear < 2020);
}

void AntiDetection::InitializeRNG() {
    std::random_device rd;
    gen.seed(rd());
}

std::wstring AntiDetection::GenerateRandomString(size_t length) {
    static const wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::wstring result;
    result.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        result += charset[dis(gen)];
    }

    return result;
}

void AntiDetection::ClearMemory(void* ptr, size_t size) {
    if (ptr && size > 0) {
        SecureZeroMemory(ptr, size);
    }
}

void AntiDetection::SecureZeroMemory(void* ptr, size_t size) {
    volatile char* p = (volatile char*)ptr;
    while (size--) {
        *p++ = 0;
    }
} 