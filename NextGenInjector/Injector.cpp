#include "Injector.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <fstream>
#include <iostream>

Injector::Injector() {}
Injector::~Injector() {}

bool Injector::InjectDLL(DWORD processId, const std::wstring& dllPath, bool autoDelete, bool delayInject) {
    if (delayInject) {
        Sleep(5000); // 5 saniye bekle
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        return false;
    }

    bool result = LoadLibraryInjection(processId, dllPath);

    if (autoDelete && result) {
        DeleteFileW(dllPath.c_str());
    }

    CloseHandle(hProcess);
    return result;
}

bool Injector::EjectDLL(DWORD processId, const std::wstring& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) return false;

    HMODULE hModule = (HMODULE)GetRemoteModuleHandle(processId, dllPath);
    if (!hModule) {
        CloseHandle(hProcess);
        return false;
    }

    // Create remote thread to call FreeLibrary
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary"),
        hModule, 0, nullptr);

    if (!hThread) {
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

bool Injector::LoadLibraryInjection(DWORD processId, const std::wstring& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        return false;
    }

    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, (dllPath.length() + 1) * sizeof(wchar_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDllPath) {
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, dllPath.c_str(),
        (dllPath.length() + 1) * sizeof(wchar_t), NULL)) {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPTHREAD_START_ROUTINE pLoadLibraryW = (LPTHREAD_START_ROUTINE)
        GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW) {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryW, pDllPath, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);

    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return exitCode != 0;
}

bool Injector::ManualMapInjection(DWORD processId, const std::wstring& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) return false;

    // Parse PE headers
    PE_HEADERS headers;
    if (!ParsePEHeaders(dllPath, headers)) {
        CloseHandle(hProcess);
        return false;
    }

    // Allocate memory for DLL
    LPVOID baseAddress = VirtualAllocEx(hProcess, nullptr,
        headers.ntHeaders.OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!baseAddress) {
        CloseHandle(hProcess);
        return false;
    }

    // Map sections
    if (!MapSections(hProcess, dllPath, headers, baseAddress)) {
        VirtualFreeEx(hProcess, baseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Fix imports and relocations
    if (!FixImports(hProcess, headers, baseAddress) ||
        !FixRelocations(hProcess, headers, baseAddress, (LPVOID)headers.ntHeaders.OptionalHeader.ImageBase)) {
        VirtualFreeEx(hProcess, baseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Execute TLS and DllMain
    if (!ExecuteTLS(hProcess, headers, baseAddress) ||
        !CallDllMain(hProcess, headers, baseAddress, DLL_PROCESS_ATTACH)) {
        VirtualFreeEx(hProcess, baseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Anti-detection measures
    ErasePEHeader(hProcess, baseAddress);
    RandomizeMemoryProtection(hProcess, baseAddress, headers.ntHeaders.OptionalHeader.SizeOfImage);

    CloseHandle(hProcess);
    return true;
}

bool Injector::NtCreateThreadInjection(DWORD processId, const std::wstring& dllPath) {
    // TODO: Implement NtCreateThreadEx injection for x64
    return false;
}

bool Injector::ThreadHijackingInjection(DWORD processId, const std::wstring& dllPath) {
    // TODO: Implement thread hijacking injection for x64
    return false;
}

bool Injector::IsProcessValid(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) return false;

    DWORD exitCode;
    if (GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hProcess);
    return true;
}

bool Injector::IsDLLValid(const std::wstring& dllPath) {
    std::ifstream file(dllPath, std::ios::binary);
    if (!file) return false;

    IMAGE_DOS_HEADER dosHeader;
    file.read((char*)&dosHeader, sizeof(IMAGE_DOS_HEADER));
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return false;

    file.seekg(dosHeader.e_lfanew);
    IMAGE_NT_HEADERS64 ntHeaders;
    file.read((char*)&ntHeaders, sizeof(IMAGE_NT_HEADERS64));
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return false;

    return true;
}

void* Injector::GetRemoteModuleHandle(DWORD processId, const std::wstring& moduleName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hSnapshot == INVALID_HANDLE_VALUE) return nullptr;

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            if (_wcsicmp(me32.szModule, moduleName.c_str()) == 0) {
                CloseHandle(hSnapshot);
                return me32.modBaseAddr;
            }
        } while (Module32NextW(hSnapshot, &me32));
    }

    CloseHandle(hSnapshot);
    return nullptr;
}

bool Injector::WriteProcessMemoryEx(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize) {
    SIZE_T bytesWritten;
    return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &bytesWritten) &&
           bytesWritten == nSize;
}

bool Injector::ReadProcessMemoryEx(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) {
    SIZE_T bytesRead;
    return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &bytesRead) &&
           bytesRead == nSize;
}

bool Injector::ParsePEHeaders(const std::wstring& dllPath, PE_HEADERS& headers) {
    std::ifstream file(dllPath, std::ios::binary);
    if (!file) return false;

    // Read DOS header
    file.read((char*)&headers.dosHeader, sizeof(IMAGE_DOS_HEADER));
    if (headers.dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return false;

    // Read NT headers
    file.seekg(headers.dosHeader.e_lfanew);
    file.read((char*)&headers.ntHeaders, sizeof(IMAGE_NT_HEADERS64));
    if (headers.ntHeaders.Signature != IMAGE_NT_SIGNATURE) return false;

    // Read section headers
    headers.sectionHeaders.resize(headers.ntHeaders.FileHeader.NumberOfSections);
    file.read((char*)headers.sectionHeaders.data(),
        headers.ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    return true;
}

bool Injector::MapSections(HANDLE hProcess, const std::wstring& dllPath, const PE_HEADERS& headers, LPVOID baseAddress) {
    std::ifstream file(dllPath, std::ios::binary);
    if (!file) return false;

    // Map each section
    for (const auto& section : headers.sectionHeaders) {
        if (section.SizeOfRawData == 0) continue;

        LPVOID sectionAddress = (LPVOID)((DWORD_PTR)baseAddress + section.VirtualAddress);
        std::vector<BYTE> sectionData(section.SizeOfRawData);

        file.seekg(section.PointerToRawData);
        file.read((char*)sectionData.data(), section.SizeOfRawData);

        if (!WriteProcessMemoryEx(hProcess, sectionAddress, sectionData.data(), section.SizeOfRawData)) {
            return false;
        }

        DWORD protection = 0;
        if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            protection = (section.Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else {
            protection = (section.Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        }

        DWORD oldProtection;
        VirtualProtectEx(hProcess, sectionAddress, section.SizeOfRawData, protection, &oldProtection);
    }

    return true;
}

bool Injector::FixImports(HANDLE hProcess, const PE_HEADERS& headers, LPVOID baseAddress) {
    // TODO: Implement import fixing for x64
    return true;
}

bool Injector::FixRelocations(HANDLE hProcess, const PE_HEADERS& headers, LPVOID baseAddress, LPVOID preferredBase) {
    // TODO: Implement relocation fixing for x64
    return true;
}

bool Injector::ExecuteTLS(HANDLE hProcess, const PE_HEADERS& headers, LPVOID baseAddress) {
    // TODO: Implement TLS execution for x64
    return true;
}

bool Injector::CallDllMain(HANDLE hProcess, const PE_HEADERS& headers, LPVOID baseAddress, DWORD reason) {
    // TODO: Implement DllMain calling for x64
    return true;
}

void Injector::ClearPEHeaders(const std::wstring& dllPath) {
    // TODO: Implement PE header clearing for x64
}

void Injector::RandomizeMemoryProtection(HANDLE hProcess, LPVOID baseAddress, SIZE_T size) {
    // TODO: Implement memory protection randomization for x64
}

void Injector::ErasePEHeader(HANDLE hProcess, LPVOID baseAddress) {
    DWORD oldProtection;
    VirtualProtectEx(hProcess, baseAddress, 0x1000, PAGE_READWRITE, &oldProtection);
    
    std::vector<BYTE> zeros(0x1000, 0);
    WriteProcessMemoryEx(hProcess, baseAddress, zeros.data(), 0x1000);
    
    VirtualProtectEx(hProcess, baseAddress, 0x1000, oldProtection, &oldProtection);
} 