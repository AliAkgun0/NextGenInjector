#pragma once

#include <string>
#include <fstream>
#include <mutex>

class Logger {
public:
    static Logger& GetInstance() {
        static Logger instance;
        return instance;
    }

    void Log(const std::wstring& message);
    void LogError(const std::wstring& message);
    void LogSuccess(const std::wstring& message);

private:
    Logger();
    ~Logger();

    std::wstring GetCurrentTime();
    void WriteToFile(const std::wstring& message);

    std::wofstream m_logFile;
    std::mutex m_mutex;
}; 