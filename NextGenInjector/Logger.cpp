#include "Logger.h"
#include <iostream>
#include <Windows.h>
#include <chrono>
#include <iomanip>
#include <sstream>

Logger& Logger::GetInstance() {
    static Logger instance;
    return instance;
}

Logger::Logger() : m_consoleOutput(true), m_fileOutput(true), m_logLevel(LOG_LEVEL_INFO) {
    m_logFile.open(L"injector.log", std::ios::out | std::ios::app);
}

Logger::~Logger() {
    if (m_logFile.is_open()) {
        m_logFile.close();
    }
}

void Logger::Log(const std::wstring& message) {
    if (m_logLevel >= LOG_LEVEL_INFO) {
        std::wstring formattedMessage = GetCurrentTime() + L" [INFO] " + message;
        WriteToConsole(formattedMessage);
        WriteToFile(formattedMessage);
    }
}

void Logger::LogError(const std::wstring& message) {
    if (m_logLevel >= LOG_LEVEL_ERROR) {
        std::wstring formattedMessage = GetCurrentTime() + L" [ERROR] " + message;
        WriteToConsole(formattedMessage);
        WriteToFile(formattedMessage);
    }
}

void Logger::LogSuccess(const std::wstring& message) {
    if (m_logLevel >= LOG_LEVEL_INFO) {
        std::wstring formattedMessage = GetCurrentTime() + L" [SUCCESS] " + message;
        WriteToConsole(formattedMessage);
        WriteToFile(formattedMessage);
    }
}

void Logger::LogWarning(const std::wstring& message) {
    if (m_logLevel >= LOG_LEVEL_WARNING) {
        std::wstring formattedMessage = GetCurrentTime() + L" [WARNING] " + message;
        WriteToConsole(formattedMessage);
        WriteToFile(formattedMessage);
    }
}

void Logger::LogDebug(const std::wstring& message) {
    if (m_logLevel >= LOG_LEVEL_DEBUG) {
        std::wstring formattedMessage = GetCurrentTime() + L" [DEBUG] " + message;
        WriteToConsole(formattedMessage);
        WriteToFile(formattedMessage);
    }
}

void Logger::SetLogFile(const std::wstring& filePath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logFile.open(filePath, std::ios::out | std::ios::app);
}

void Logger::EnableConsoleOutput(bool enable) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_consoleOutput = enable;
}

void Logger::EnableFileOutput(bool enable) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_fileOutput = enable;
}

void Logger::SetLogLevel(int level) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logLevel = level;
}

void Logger::WriteToFile(const std::wstring& message) {
    if (!m_fileOutput) return;

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_logFile.is_open()) {
        m_logFile << message << std::endl;
        m_logFile.flush();
    }
}

void Logger::WriteToConsole(const std::wstring& message) {
    if (!m_consoleOutput) return;

    std::lock_guard<std::mutex> lock(m_mutex);
    std::wcout << message << std::endl;
}

std::wstring Logger::GetCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::wstringstream ss;
    ss << std::put_time(std::localtime(&time), L"%Y-%m-%d %H:%M:%S");
    ss << L'.' << std::setfill(L'0') << std::setw(3) << ms.count();
    return ss.str();
}

std::wstring Logger::FormatMessage(const std::wstring& message, const std::wstring& prefix) {
    return GetCurrentTime() + L" " + prefix + L" " + message;
} 