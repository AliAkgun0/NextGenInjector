#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <winternl.h>
#include <iphlpapi.h>
#include <tchar.h>

// Undocumented Windows structures
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

// PEB structure
typedef struct _PEB_LITE {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB_LITE, *PPEB_LITE;

// Process information class
typedef enum _CUSTOM_PROCESSINFOCLASS {
    CustomProcessBasicInformation = 0,
    CustomProcessDebugPort = 7,
    CustomProcessWow64Information = 26,
    CustomProcessImageFileName = 27,
    CustomProcessBreakOnTermination = 29,
    CustomProcessDebugObjectHandle = 30,
    CustomProcessDebugFlags = 31
} CUSTOM_PROCESSINFOCLASS;

// System information class
typedef enum _CUSTOM_SYSTEM_INFORMATION_CLASS {
    CustomSystemBasicInformation = 0,
    CustomSystemPerformanceInformation = 2,
    CustomSystemTimeOfDayInformation = 3,
    CustomSystemProcessInformation = 5,
    CustomSystemProcessorPerformanceInformation = 8,
    CustomSystemInterruptInformation = 23,
    CustomSystemExceptionInformation = 33,
    CustomSystemRegistryQuotaInformation = 37,
    CustomSystemLookasideInformation = 45,
    CustomSystemKernelDebuggerInformation = 35
} CUSTOM_SYSTEM_INFORMATION_CLASS;

class AntiDetection {
public:
    static AntiDetection& GetInstance() {
        static AntiDetection instance;
        return instance;
    }

    bool Initialize();
    bool IsDebuggerPresent();
    bool IsVirtualMachine();
    bool IsSandbox();
    bool IsBeingDebugged();
    void RandomizeWindowTitle(HWND hwnd);
    void RandomizeWindowClass(HWND hwnd);
    void ClearMemoryTraces();
    void EncryptStrings();
    void DecryptStrings();
    std::wstring GenerateRandomString(size_t length);

private:
    AntiDetection();
    ~AntiDetection();
    AntiDetection(const AntiDetection&) = delete;
    AntiDetection& operator=(const AntiDetection&) = delete;

    // Debugger detection methods
    bool CheckIsDebuggerPresent();
    bool CheckNtGlobalFlag();
    bool CheckHeapFlags();
    bool CheckProcessDebugFlags();
    bool CheckProcessDebugObject();
    bool CheckSystemDebugger();
    bool CheckHardwareBreakpoints();
    bool CheckSoftwareBreakpoints();

    // VM detection methods
    bool CheckCPUID();
    bool CheckRegistry();
    bool CheckDrivers();
    bool CheckProcesses();
    bool CheckMACAddress();
    bool CheckBIOS();
    bool CheckDiskSize();
    bool CheckMemorySize();

    // Sandbox detection methods
    bool CheckUserNames();
    bool CheckSystemInfo();
    bool CheckNetworkInfo();
    bool CheckInstalledSoftware();
    bool CheckRunningProcesses();
    bool CheckFileSystem();
    bool CheckRegistryKeys();
    bool CheckSystemTime();

    // String encryption
    struct EncryptedString {
        std::vector<BYTE> data;
        size_t key;
    };

    std::vector<EncryptedString> m_encryptedStrings;
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;

    // Helper methods
    void InitializeRNG();
    std::vector<BYTE> XOREncrypt(const std::string& str, size_t key);
    std::string XORDecrypt(const std::vector<BYTE>& data, size_t key);
    void ClearMemory(void* ptr, size_t size);
    void SecureZeroMemory(void* ptr, size_t size);
}; 