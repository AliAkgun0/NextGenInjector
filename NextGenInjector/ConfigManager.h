#pragma once

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <filesystem>

struct Profile {
    std::wstring name;
    std::wstring dllPath;
    std::wstring processName;
    bool autoDelete;
    bool delayInject;
    std::wstring injectionMethod;
};

class ConfigManager {
public:
    static ConfigManager& GetInstance() {
        static ConfigManager instance;
        return instance;
    }

    ConfigManager();
    ~ConfigManager();

    bool LoadConfig(const std::wstring& path = L"");
    bool SaveConfig();
    void SetDefaultConfig();

    std::wstring GetString(const std::wstring& key, const std::wstring& defaultValue = L"") const;
    int GetInt(const std::wstring& key, int defaultValue = 0) const;
    bool GetBool(const std::wstring& key, bool defaultValue = false) const;

    void SetString(const std::wstring& key, const std::wstring& value);
    void SetInt(const std::wstring& key, int value);
    void SetBool(const std::wstring& key, bool value);

    std::vector<std::wstring> GetRecentDLLs() const;
    void SetRecentDLLs(const std::vector<std::wstring>& dlls);
    void AddRecentDLL(const std::wstring& dllPath);

    std::vector<Profile> GetProfiles() const;
    void SetProfiles(const std::vector<Profile>& profiles);
    void AddProfile(const std::wstring& profileName);

    bool GetAutoDeleteDLL() const;
    void SetAutoDeleteDLL(bool value);

    bool GetDelayInject() const;
    void SetDelayInject(bool value);

    std::wstring GetInjectionMethod() const;
    void SetInjectionMethod(const std::wstring& value);

    std::wstring GetLastDLLPath() const;
    void SetLastDLLPath(const std::wstring& value);

private:
    static constexpr const wchar_t* DEFAULT_CONFIG_FILE = L"config.json";
    static constexpr int MAX_RECENT_DLLS = 10;

    std::wstring m_configPath;
    std::map<std::wstring, std::wstring> m_stringValues;
    std::map<std::wstring, int> m_intValues;
    std::map<std::wstring, bool> m_boolValues;
    std::vector<std::wstring> m_recentDLLs;
    std::vector<Profile> m_profiles;

    std::string WideStringToUTF8(const std::wstring& str) const;
    std::wstring UTF8ToWideString(const std::string& str) const;
}; 