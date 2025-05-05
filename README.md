🧪 Development Notice

⚠️ This project is currently in active development and may not be fully functional at this stage.
Some features are still experimental, and certain injection methods or GUI components might not behave as expected.
I'm actively working on identifying and fixing the remaining bugs, improving stability, and finalizing all core systems.

If you encounter issues or have suggestions, feel free to open an issue or contribute via pull requests — all constructive feedback is welcome!
# 🚀 NextGen Injector

> A high-performance, stealthy and customizable DLL injection framework written in modern C++. Designed with advanced injection techniques, anti-detection layers, and a user-friendly Win32 GUI.

---

## 🎯 Project Overview

**NextGen Injector** is a feature-rich DLL injection system designed to bypass modern anti-cheat mechanisms using advanced injection methods and stealth techniques. It is built entirely in **C++** with a lightweight **Win32 API GUI** and includes powerful automation, logging, and configuration features.

---

## 📌 Features

### 🔧 1. Core Architecture
- Fully developed in modern C++.
- Lightweight Win32 GUI (no console window).
- Modular injection engine with support for multiple methods.

---

### 🚀 2. Supported Injection Methods
- **LoadLibraryA** → Simple & fast method.
- **Manual Mapping** → Direct PE loading in memory (harder to detect).
- **NtCreateThreadEx** → Stealthier thread-based injection.
- **Thread Hijacking** → Code injection into existing remote threads.
- *(Optional)* Kernel-mode injection via driver for maximum stealth.

---

### 🛡️ 3. Anti-Detection Layers
- Runtime **string encryption** (XOR / AES).
- Randomized **window title & class names** on each launch.
- **Anti-debug**, **VM**, and **sandbox detection**.
- **DLL auto-delete** using `DeleteFileW` post-injection.
- Obfuscated in-memory **configuration system**.

---

### 📦 4. DLL Management
- Multiple DLL injection support using `std::vector`.
- Manual **DLL execution order** selection.
- Export function selection: `Main()`, `Init()`, etc.

---

### 🧩 5. Automation & Profiles
- JSON-based profile loading via `nlohmann/json.hpp`.
- **Auto-inject** when target process starts.
- Wait for PID or process name (polling or hook).

---

### 🔐 6. Security & Logging
- **SHA-256 hash verification** for integrity checks.
- Injection logs: process ID, timestamp, status.
- *(Optional)* Discord Webhook support for real-time alerts.

---

### 🔬 7. Advanced Techniques
- Manual PE parsing and mapping.
- Use of **remote syscalls** (`Nt*` functions).
- Memory scanning within target processes.
- Protection with `PAGE_NOACCESS`, etc.

---

## 🖼️ GUI (Win32) Highlights

### 🎨 UI Components
- **MainWindow title:** `NextGen Injector`
- **ComboBox**: Live process list
- **TextBox**: Manual PID entry
- **Buttons**: `Refresh`, `Select DLL`, `Inject`
- **CheckBoxes**: `Auto delete DLL`, `Delay injection`
- **DropDown**: Select injection method (LoadLibraryA, ManualMap, etc.)

### 💄 UX & Styling
- Dark mode: `RGB(30, 30, 30)`
- Font: `Segoe UI`, 9pt
- Hover effects on buttons
- Custom cursor support (`LoadCursorFromFile`)
- Smooth animations via `AnimateWindow`

---

## 🛠️ Build Configuration
- Must be compiled in **Release** mode.
- Support for both `x86` and `x64`.
- Linker settings: `/INCREMENTAL:NO`
- Small, unsigned executable.
- Optional: Pack with **UPX** for size reduction.

---

## 🔒 Additional Stealth Features
- XOR or AES runtime string encryption.
- Random executable name and window title.
- **PE Header erasure** (`ErasePEHeader`).
- Memory wiping with `ZeroMemory` or `SecureZeroMemory`.
- Optional: **Process hollowing**, **unlinking**, etc.

---

## 📁 Folder Structure (Suggested)
NextGenInjector/
│
├── src/ # Source code
├── include/ # Header files
├── profiles/ # JSON configs
├── libs/ # Dependencies
├── build/ # Output binaries
└── README.md # Project description

---

## ⚠️ Disclaimer

This project is for **educational and research purposes only**.  
We do **not condone** nor support illegal use of this software, including usage to bypass anti-cheat protections or violate EULA agreements of any software.

> ⚠️ Use at your own risk.

---

## 📬 Contact & Contributions
Feel free to open issues or submit pull requests for enhancements.  
Questions? Reach out via GitHub discussions or issues tab.

---
