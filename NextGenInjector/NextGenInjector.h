#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>
#include <random>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include "ConfigManager.h"
#include "AntiDetection.h"
#include "resource.h"
#include "framework.h"

// Global Variables:
extern HINSTANCE hInst;                                // current instance
extern WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
extern WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Forward declarations
class Injector;
class AntiDetection;
class Logger;
class ConfigManager;

// Constants
constexpr auto WINDOW_CLASS_NAME = L"NextGenInjectorClass";
constexpr auto WINDOW_TITLE = L"NextGen Injector";
constexpr auto WINDOW_WIDTH = 800;
constexpr auto WINDOW_HEIGHT = 600;

// Custom colors
constexpr COLORREF BACKGROUND_COLOR = RGB(30, 30, 30);
constexpr COLORREF TEXT_COLOR = RGB(200, 200, 200);
constexpr COLORREF BUTTON_COLOR = RGB(50, 50, 50);
constexpr COLORREF BUTTON_HOVER_COLOR = RGB(70, 70, 70);

// Injection methods
enum class InjectionMethod {
    LOAD_LIBRARY,
    MANUAL_MAP,
    NT_CREATE_THREAD,
    THREAD_HIJACKING
};

// Main application class
class NextGenInjector {
public:
    static NextGenInjector& GetInstance() {
        static NextGenInjector instance;
        return instance;
    }

    bool Initialize(HINSTANCE hInstance);
    int Run();

private:
    NextGenInjector() = default;
    ~NextGenInjector() = default;

    ATOM MyRegisterClass(HINSTANCE hInstance);
    bool InitInstance(HINSTANCE hInstance, int nCmdShow);
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    static INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

    HINSTANCE m_hInstance;
    HWND m_hWnd;
    WCHAR m_szTitle[MAX_LOADSTRING];
    WCHAR m_szWindowClass[MAX_LOADSTRING];

    bool CreateMainWindow();
    bool CreateProcessList();
    bool CreatePIDInput();
    bool CreateDLLPathInput();
    bool CreateInjectionMethodCombo();
    bool CreateAutoDeleteCheck();
    bool CreateDelayInjectCheck();
    bool CreateInjectButton();
    bool CreateRefreshButton();
    bool CreateSelectDLLButton();

    void RandomizeWindowTitle();
    void UpdateProcessList();
    void OnInject();
    void OnRefresh();
    void OnSelectDLL();
    void OnAutoDeleteChanged();
    void OnDelayInjectChanged();

    HWND m_processList;
    HWND m_pidEdit;
    HWND m_dllPathEdit;
    HWND m_injectionMethodCombo;
    HWND m_autoDeleteCheck;
    HWND m_delayInjectCheck;
    HWND m_injectButton;
    HWND m_refreshButton;
    HWND m_selectDLLButton;

    std::unique_ptr<ConfigManager> m_configManager;
    std::vector<std::wstring> m_recentDLLs;
    std::wstring m_currentDLLPath;
    bool m_autoDelete;
    bool m_delayInject;
    int m_injectionMethod;

    static constexpr int WM_UPDATE_PROCESS_LIST = WM_USER + 1;
    static constexpr int WM_INJECT_COMPLETE = WM_USER + 2;
    static constexpr int WM_INJECT_ERROR = WM_USER + 3;
};

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
