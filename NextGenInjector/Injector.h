#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>

class Injector {
public:
    static Injector& GetInstance() {
        static Injector instance;
        return instance;
    }

    bool InjectDLL(DWORD processId, const std::wstring& dllPath, bool autoDelete = false, bool delayInject = false);
    bool EjectDLL(DWORD processId, const std::wstring& dllPath);

private:
    Injector() = default;
    ~Injector() = default;

    // Basic injection methods
    bool LoadLibraryInjection(DWORD processId, const std::wstring& dllPath);
    bool ManualMapInjection(DWORD processId, const std::wstring& dllPath);
    bool NtCreateThreadInjection(DWORD processId, const std::wstring& dllPath);
    bool ThreadHijackingInjection(DWORD processId, const std::wstring& dllPath);

    // Helper methods
    bool IsProcessValid(DWORD processId);
    bool IsDLLValid(const std::wstring& dllPath);
    void* GetRemoteModuleHandle(DWORD processId, const std::wstring& moduleName);
    bool WriteProcessMemoryEx(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize);
    bool ReadProcessMemoryEx(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize);

    // Manual mapping helpers
    struct PE_HEADERS {
        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS64 ntHeaders;
        std::vector<IMAGE_SECTION_HEADER> sectionHeaders;
    };

    bool ParsePEHeaders(const std::wstring& dllPath, PE_HEADERS& headers);
    bool MapSections(HANDLE hProcess, const std::wstring& dllPath, const PE_HEADERS& headers, LPVOID baseAddress);
    bool FixImports(HANDLE hProcess, const PE_HEADERS& headers, LPVOID baseAddress);
    bool FixRelocations(HANDLE hProcess, const PE_HEADERS& headers, LPVOID baseAddress, LPVOID preferredBase);
    bool ExecuteTLS(HANDLE hProcess, const PE_HEADERS& headers, LPVOID baseAddress);
    bool CallDllMain(HANDLE hProcess, const PE_HEADERS& headers, LPVOID baseAddress, DWORD reason);

    // Anti-detection helpers
    void ClearPEHeaders(const std::wstring& dllPath);
    void RandomizeMemoryProtection(HANDLE hProcess, LPVOID baseAddress, SIZE_T size);
    void ErasePEHeader(HANDLE hProcess, LPVOID baseAddress);
}; 