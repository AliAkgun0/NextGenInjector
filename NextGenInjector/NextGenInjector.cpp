// NextGenInjector.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "NextGenInjector.h"
#include "Injector.h"
#include "AntiDetection.h"
#include "Logger.h"
#include "ConfigManager.h"
#include <commctrl.h>
#include <commdlg.h>
#include "resource.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <algorithm>
#include <shlobj.h>
#include <sstream>
#include <iomanip>
#include <Psapi.h>
#include <iphlpapi.h>
#include <windowsx.h>
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Iphlpapi.lib")

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name
HWND hMainWnd;
HWND hProcessList;
HWND hPIDEdit;
HWND hDLLPathEdit;
HWND hInjectionMethodCombo;
HWND hAutoDeleteCheck;
HWND hDelayInjectCheck;
HWND hInjectButton;
HWND hRefreshButton;
HWND hSelectDLLButton;

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_NEXTGENINJECTOR, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance(hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_NEXTGENINJECTOR));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}

//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_NEXTGENINJECTOR));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_NEXTGENINJECTOR);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    hInst = hInstance; // Store instance handle in our global variable

    HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

    if (!hWnd)
    {
        return FALSE;
    }

    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    if (!InitCommonControlsEx(&icex)) {
        MessageBoxW(NULL, L"Ortak kontroller başlatılamadı!", L"Hata", MB_ICONERROR);
        return FALSE;
    }

    // Initialize NextGenInjector instance
    auto& injector = NextGenInjector::GetInstance();
    if (!injector.Initialize()) {
        MessageBoxW(NULL, L"NextGenInjector başlatılamadı!", L"Hata", MB_ICONERROR);
        return FALSE;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code that uses hdc here...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

NextGenInjector::NextGenInjector() 
    : m_hwnd(nullptr)
    , m_processList(nullptr)
    , m_pidEdit(nullptr)
    , m_dllPathEdit(nullptr)
    , m_injectionMethodCombo(nullptr)
    , m_autoDeleteCheck(nullptr)
    , m_delayInjectCheck(nullptr)
    , m_injectButton(nullptr)
    , m_refreshButton(nullptr)
    , m_selectDLLButton(nullptr)
    , m_autoDelete(false)
    , m_delayInject(false)
    , m_injectionMethod(0) {
}

NextGenInjector::~NextGenInjector() {
    Cleanup();
}

bool NextGenInjector::Initialize() {
    try {
        // Initialize common controls
        INITCOMMONCONTROLSEX icex;
        icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
        icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
        if (!InitCommonControlsEx(&icex)) {
            MessageBoxW(NULL, L"Ortak kontroller başlatılamadı!", L"Hata", MB_ICONERROR);
            return false;
        }

        // Create main window
        if (!CreateMainWindow()) {
            MessageBoxW(NULL, L"Ana pencere oluşturulamadı!", L"Hata", MB_ICONERROR);
            return false;
        }

        // Create UI components
        if (!CreateProcessList() ||
            !CreatePIDInput() ||
            !CreateDLLPathInput() ||
            !CreateInjectionMethodCombo() ||
            !CreateAutoDeleteCheck() ||
            !CreateDelayInjectCheck() ||
            !CreateInjectButton() ||
            !CreateRefreshButton() ||
            !CreateSelectDLLButton()) {
            MessageBoxW(NULL, L"UI bileşenleri oluşturulamadı!", L"Hata", MB_ICONERROR);
            return false;
        }

        // Initialize config manager
        m_configManager = std::make_unique<ConfigManager>();
        if (!m_configManager->LoadConfig(L"config.json")) {
            m_configManager->SetDefaultConfig();
        }

        // Load recent DLLs
        m_recentDLLs = m_configManager->GetRecentDLLs();

        // Randomize window title
        RandomizeWindowTitle();

        return true;
    }
    catch (const std::exception& e) {
        std::string error = "Beklenmeyen hata: ";
        error += e.what();
        MessageBoxA(NULL, error.c_str(), "Hata", MB_ICONERROR);
        return false;
    }
    catch (...) {
        MessageBoxW(NULL, L"Bilinmeyen bir hata oluştu!", L"Hata", MB_ICONERROR);
        return false;
    }
}

bool NextGenInjector::Run(HINSTANCE hInstance, int nCmdShow) {
    if (!Initialize()) {
        return false;
    }

    // ... rest of the implementation ...

    return true;
}

void NextGenInjector::Cleanup() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

bool NextGenInjector::CreateMainWindow() {
    WNDCLASSEX wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"NextGenInjector";
    wc.hIcon = LoadIcon(wc.hInstance, MAKEINTRESOURCE(IDI_ICON1));
    wc.hIconSm = LoadIcon(wc.hInstance, MAKEINTRESOURCE(IDI_ICON1));

    if (!RegisterClassEx(&wc)) {
        return false;
    }

    m_hwnd = CreateWindowEx(
        0,
        L"NextGenInjector",
        L"NextGen Injector",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        nullptr,
        nullptr,
        wc.hInstance,
        this
    );

    if (!m_hwnd) {
        return false;
    }

    ShowWindow(m_hwnd, SW_SHOW);
    UpdateWindow(m_hwnd);

    return true;
}

bool NextGenInjector::CreateProcessList() {
    m_processList = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEW,
        L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
        10, 10, 760, 200,
        m_hwnd,
        (HMENU)IDC_PROCESS_LIST,
        GetModuleHandle(nullptr),
        nullptr
    );

    if (!m_processList) {
        return false;
    }

    // Add columns
    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    lvc.iSubItem = 0;
    lvc.cx = 100;
    lvc.pszText = (LPWSTR)L"PID";
    ListView_InsertColumn(m_processList, 0, &lvc);

    lvc.iSubItem = 1;
    lvc.cx = 300;
    lvc.pszText = (LPWSTR)L"Process Name";
    ListView_InsertColumn(m_processList, 1, &lvc);

    lvc.iSubItem = 2;
    lvc.cx = 200;
    lvc.pszText = (LPWSTR)L"Architecture";
    ListView_InsertColumn(m_processList, 2, &lvc);

    lvc.iSubItem = 3;
    lvc.cx = 160;
    lvc.pszText = (LPWSTR)L"Memory Usage";
    ListView_InsertColumn(m_processList, 3, &lvc);

    return true;
}

bool NextGenInjector::CreatePIDInput() {
    m_pidEdit = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | ES_NUMBER,
        10, 220, 100, 25,
        m_hwnd,
        (HMENU)IDC_PID_EDIT,
        GetModuleHandle(nullptr),
        nullptr
    );

    return m_pidEdit != nullptr;
}

bool NextGenInjector::CreateDLLPathInput() {
    m_dllPathEdit = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        120, 220, 500, 25,
        m_hwnd,
        (HMENU)IDC_DLL_PATH_EDIT,
        GetModuleHandle(nullptr),
        nullptr
    );

    return m_dllPathEdit != nullptr;
}

bool NextGenInjector::CreateInjectionMethodCombo() {
    m_injectionMethodCombo = CreateWindowEx(
        0,
        L"COMBOBOX",
        L"",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
        630, 220, 140, 200,
        m_hwnd,
        (HMENU)IDC_INJECTION_METHOD_COMBO,
        GetModuleHandle(nullptr),
        nullptr
    );

    if (!m_injectionMethodCombo) {
        return false;
    }

    // Add injection methods
    SendMessage(m_injectionMethodCombo, CB_ADDSTRING, 0, (LPARAM)L"LoadLibrary");
    SendMessage(m_injectionMethodCombo, CB_ADDSTRING, 0, (LPARAM)L"Manual Map");
    SendMessage(m_injectionMethodCombo, CB_ADDSTRING, 0, (LPARAM)L"Thread Hijack");
    SendMessage(m_injectionMethodCombo, CB_SETCURSEL, 0, 0);

    return true;
}

bool NextGenInjector::CreateAutoDeleteCheck() {
    m_autoDeleteCheck = CreateWindowEx(
        0,
        L"BUTTON",
        L"Auto Delete",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        10, 255, 100, 25,
        m_hwnd,
        (HMENU)IDC_AUTO_DELETE_CHECK,
        GetModuleHandle(nullptr),
        nullptr
    );

    return m_autoDeleteCheck != nullptr;
}

bool NextGenInjector::CreateDelayInjectCheck() {
    m_delayInjectCheck = CreateWindowEx(
        0,
        L"BUTTON",
        L"Delay Inject",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        120, 255, 100, 25,
        m_hwnd,
        (HMENU)IDC_DELAY_INJECT_CHECK,
        GetModuleHandle(nullptr),
        nullptr
    );

    return m_delayInjectCheck != nullptr;
}

bool NextGenInjector::CreateInjectButton() {
    m_injectButton = CreateWindowEx(
        0,
        L"BUTTON",
        L"Inject",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        630, 255, 140, 25,
        m_hwnd,
        (HMENU)IDC_INJECT_BUTTON,
        GetModuleHandle(nullptr),
        nullptr
    );

    return m_injectButton != nullptr;
}

bool NextGenInjector::CreateRefreshButton() {
    m_refreshButton = CreateWindowEx(
        0,
        L"BUTTON",
        L"Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        630, 290, 140, 25,
        m_hwnd,
        (HMENU)IDC_REFRESH_BUTTON,
        GetModuleHandle(nullptr),
        nullptr
    );

    return m_refreshButton != nullptr;
}

bool NextGenInjector::CreateSelectDLLButton() {
    m_selectDLLButton = CreateWindowEx(
        0,
        L"BUTTON",
        L"Select DLL",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        630, 220, 140, 25,
        m_hwnd,
        (HMENU)IDC_SELECT_DLL_BUTTON,
        GetModuleHandle(nullptr),
        nullptr
    );

    return m_selectDLLButton != nullptr;
}

void NextGenInjector::RandomizeWindowTitle() {
    std::wstring title = AntiDetection::GetInstance().GenerateRandomString(16);
    SetWindowText(m_hwnd, title.c_str());
}

void NextGenInjector::UpdateProcessList() {
    // Clear existing items
    ListView_DeleteAllItems(m_processList);

    // Get process list
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            LVITEM lvi = { 0 };
            lvi.mask = LVIF_TEXT;
            lvi.iItem = ListView_GetItemCount(m_processList);

            // Add PID
            std::wstring pidStr = std::to_wstring(pe32.th32ProcessID);
            lvi.iSubItem = 0;
            lvi.pszText = const_cast<LPWSTR>(pidStr.c_str());
            ListView_InsertItem(m_processList, &lvi);

            // Add process name
            lvi.iSubItem = 1;
            lvi.pszText = pe32.szExeFile;
            ListView_SetItem(m_processList, &lvi);

            // Add architecture
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                BOOL isWow64;
                IsWow64Process(hProcess, &isWow64);
                CloseHandle(hProcess);

                lvi.iSubItem = 2;
                lvi.pszText = isWow64 ? (LPWSTR)L"x86" : (LPWSTR)L"x64";
                ListView_SetItem(m_processList, &lvi);
            }

            // Add memory usage
            HANDLE hProcessMem = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcessMem) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcessMem, &pmc, sizeof(pmc))) {
                    std::wstringstream ss;
                    ss << std::fixed << std::setprecision(2) << (pmc.WorkingSetSize / 1024.0 / 1024.0) << L" MB";
                    lvi.iSubItem = 3;
                    lvi.pszText = const_cast<LPWSTR>(ss.str().c_str());
                    ListView_SetItem(m_processList, &lvi);
                }
                CloseHandle(hProcessMem);
            }

        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
}

void NextGenInjector::OnInject() {
    // Get selected process
    int selectedIndex = ListView_GetNextItem(m_processList, -1, LVNI_SELECTED);
    if (selectedIndex == -1) {
        MessageBox(m_hwnd, L"Please select a process", L"Error", MB_ICONERROR);
        return;
    }

    LVITEM lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    lvi.iItem = selectedIndex;
    lvi.iSubItem = 0;
    wchar_t pidStr[32];
    lvi.pszText = pidStr;
    lvi.cchTextMax = sizeof(pidStr) / sizeof(wchar_t);
    ListView_GetItem(m_processList, &lvi);

    DWORD pid = _wtoi(pidStr);

    // Get DLL path
    wchar_t dllPath[MAX_PATH];
    GetWindowText(m_dllPathEdit, dllPath, MAX_PATH);
    if (wcslen(dllPath) == 0) {
        MessageBox(m_hwnd, L"Please select a DLL", L"Error", MB_ICONERROR);
        return;
    }

    // Get injection method
    int method = SendMessage(m_injectionMethodCombo, CB_GETCURSEL, 0, 0);

    // TODO: Implement injection logic
    MessageBox(m_hwnd, L"Injection not implemented yet", L"Info", MB_ICONINFORMATION);
}

void NextGenInjector::OnRefresh() {
    UpdateProcessList();
}

void NextGenInjector::OnSelectDLL() {
    wchar_t dllPath[MAX_PATH] = { 0 };

    OPENFILENAME ofn = { 0 };
    ofn.lStructSize = sizeof(OPENFILENAME);
    ofn.hwndOwner = m_hwnd;
    ofn.lpstrFilter = L"DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = dllPath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrDefExt = L"dll";

    if (GetOpenFileName(&ofn)) {
        SetWindowText(m_dllPathEdit, dllPath);
        m_currentDLLPath = dllPath;

        // Add to recent DLLs
        if (std::find(m_recentDLLs.begin(), m_recentDLLs.end(), dllPath) == m_recentDLLs.end()) {
            m_recentDLLs.insert(m_recentDLLs.begin(), dllPath);
            if (m_recentDLLs.size() > 10) {
                m_recentDLLs.pop_back();
            }
            m_configManager->SetRecentDLLs(m_recentDLLs);
        }
    }
}

void NextGenInjector::OnAutoDeleteChanged() {
    m_autoDelete = SendMessage(m_autoDeleteCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void NextGenInjector::OnDelayInjectChanged() {
    m_delayInject = SendMessage(m_delayInjectCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

LRESULT CALLBACK NextGenInjector::WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    NextGenInjector* pThis = nullptr;

    if (msg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pThis = (NextGenInjector*)pCreate->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)pThis);
    } else {
        pThis = (NextGenInjector*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    }

    if (pThis) {
        switch (msg) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
            case IDC_INJECT_BUTTON:
                pThis->OnInject();
                break;
            case IDC_REFRESH_BUTTON:
                pThis->OnRefresh();
                break;
            case IDC_SELECT_DLL_BUTTON:
                pThis->OnSelectDLL();
                break;
            case IDC_AUTO_DELETE_CHECK:
                pThis->OnAutoDeleteChanged();
                break;
            case IDC_DELAY_INJECT_CHECK:
                pThis->OnDelayInjectChanged();
                break;
            }
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        case WM_UPDATE_PROCESS_LIST:
            pThis->UpdateProcessList();
            break;

        case WM_INJECT_COMPLETE:
            MessageBox(hwnd, L"Injection successful", L"Success", MB_ICONINFORMATION);
            break;

        case WM_INJECT_ERROR:
            MessageBox(hwnd, (LPCWSTR)lParam, L"Error", MB_ICONERROR);
            break;
        }
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}
