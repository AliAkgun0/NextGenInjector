// header.h : include file for standard system include files,
// or project specific include files
//

#pragma once

#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00

#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <string>
#include <vector>

#define MAX_LOADSTRING 100
