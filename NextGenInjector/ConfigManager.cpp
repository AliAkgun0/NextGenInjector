#include "ConfigManager.h"
#include <Windows.h>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <algorithm>

ConfigManager::ConfigManager() {
    m_configPath = DEFAULT_CONFIG_FILE;
    SetDefaultConfig();
}

ConfigManager::~ConfigManager() {
    SaveConfig();
}

bool ConfigManager::LoadConfig(const std::wstring& path) {
    if (!path.empty()) {
        m_configPath = path;
    }

    if (!std::filesystem::exists(m_configPath)) {
        SetDefaultConfig();
        return true;
    }

    std::ifstream file(m_configPath);
    if (!file.is_open()) {
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // TODO: Implement JSON parsing
    // For now, just set default values
    SetDefaultConfig();
    return true;
}

bool ConfigManager::SaveConfig() {
    std::ofstream file(m_configPath);
    if (!file.is_open()) {
        return false;
    }

    // Convert wide strings to UTF-8 before writing
    for (const auto& pair : m_stringValues) {
        std::string key = WideStringToUTF8(pair.first);
        std::string value = WideStringToUTF8(pair.second);
        file << key << "=" << value << std::endl;
    }
    for (const auto& pair : m_intValues) {
        std::string key = WideStringToUTF8(pair.first);
        file << key << "=" << pair.second << std::endl;
    }
    for (const auto& pair : m_boolValues) {
        std::string key = WideStringToUTF8(pair.first);
        file << key << "=" << (pair.second ? "true" : "false") << std::endl;
    }

    // Save recent DLLs
    file << "[RecentDLLs]" << std::endl;
    for (const auto& dll : m_recentDLLs) {
        std::string dllPath = WideStringToUTF8(dll);
        file << dllPath << std::endl;
    }

    // Save profiles
    file << "[Profiles]" << std::endl;
    for (const auto& profile : m_profiles) {
        std::string name = WideStringToUTF8(profile.name);
        std::string dllPath = WideStringToUTF8(profile.dllPath);
        std::string processName = WideStringToUTF8(profile.processName);
        std::string injectionMethod = WideStringToUTF8(profile.injectionMethod);
        file << "Name=" << name << std::endl;
        file << "DLLPath=" << dllPath << std::endl;
        file << "ProcessName=" << processName << std::endl;
        file << "AutoDelete=" << (profile.autoDelete ? "true" : "false") << std::endl;
        file << "DelayInject=" << (profile.delayInject ? "true" : "false") << std::endl;
        file << "InjectionMethod=" << injectionMethod << std::endl;
        file << "---" << std::endl;
    }

    file.close();
    return true;
}

void ConfigManager::SetDefaultConfig() {
    m_stringValues.clear();
    m_intValues.clear();
    m_boolValues.clear();
    m_recentDLLs.clear();
    m_profiles.clear();

    SetAutoDeleteDLL(false);
    SetDelayInject(false);
    SetInjectionMethod(L"LoadLibrary");
    SetLastDLLPath(L"");
}

std::wstring ConfigManager::GetString(const std::wstring& key, const std::wstring& defaultValue) const {
    auto it = m_stringValues.find(key);
    if (it != m_stringValues.end()) {
        return it->second;
    }
    return defaultValue;
}

int ConfigManager::GetInt(const std::wstring& key, int defaultValue) const {
    auto it = m_intValues.find(key);
    if (it != m_intValues.end()) {
        return it->second;
    }
    return defaultValue;
}

bool ConfigManager::GetBool(const std::wstring& key, bool defaultValue) const {
    auto it = m_boolValues.find(key);
    if (it != m_boolValues.end()) {
        return it->second;
    }
    return defaultValue;
}

void ConfigManager::SetString(const std::wstring& key, const std::wstring& value) {
    m_stringValues[key] = value;
}

void ConfigManager::SetInt(const std::wstring& key, int value) {
    m_intValues[key] = value;
}

void ConfigManager::SetBool(const std::wstring& key, bool value) {
    m_boolValues[key] = value;
}

std::vector<std::wstring> ConfigManager::GetRecentDLLs() const {
    return m_recentDLLs;
}

void ConfigManager::SetRecentDLLs(const std::vector<std::wstring>& dlls) {
    m_recentDLLs = dlls;
}

void ConfigManager::AddRecentDLL(const std::wstring& dllPath) {
    // Remove if already exists
    m_recentDLLs.erase(std::remove(m_recentDLLs.begin(), m_recentDLLs.end(), dllPath), m_recentDLLs.end());
    
    // Add to beginning
    m_recentDLLs.insert(m_recentDLLs.begin(), dllPath);
    
    // Limit size
    if (m_recentDLLs.size() > MAX_RECENT_DLLS) {
        m_recentDLLs.resize(MAX_RECENT_DLLS);
    }
}

std::vector<Profile> ConfigManager::GetProfiles() const {
    return m_profiles;
}

void ConfigManager::SetProfiles(const std::vector<Profile>& profiles) {
    m_profiles = profiles;
}

void ConfigManager::AddProfile(const std::wstring& profileName) {
    // Remove if already exists
    m_profiles.erase(std::remove_if(m_profiles.begin(), m_profiles.end(),
        [&](const Profile& p) { return p.name == profileName; }), m_profiles.end());
    
    // Add new profile
    Profile profile;
    profile.name = profileName;
    m_profiles.insert(m_profiles.begin(), profile);
}

bool ConfigManager::GetAutoDeleteDLL() const {
    return GetBool(L"autoDeleteDLL", false);
}

void ConfigManager::SetAutoDeleteDLL(bool value) {
    SetBool(L"autoDeleteDLL", value);
}

bool ConfigManager::GetDelayInject() const {
    return GetBool(L"delayInject", false);
}

void ConfigManager::SetDelayInject(bool value) {
    SetBool(L"delayInject", value);
}

std::wstring ConfigManager::GetInjectionMethod() const {
    return GetString(L"injectionMethod", L"LoadLibrary");
}

void ConfigManager::SetInjectionMethod(const std::wstring& value) {
    SetString(L"injectionMethod", value);
}

std::wstring ConfigManager::GetLastDLLPath() const {
    return GetString(L"lastDLLPath", L"");
}

void ConfigManager::SetLastDLLPath(const std::wstring& value) {
    SetString(L"lastDLLPath", value);
}

std::string ConfigManager::WideStringToUTF8(const std::wstring& str) const {
    if (str.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &str[0], (int)str.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::wstring ConfigManager::UTF8ToWideString(const std::string& str) const {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
} 