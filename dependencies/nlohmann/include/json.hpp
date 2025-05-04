#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <stdexcept>

namespace nlohmann {
    class json {
    public:
        json() = default;
        json(const json&) = default;
        json(json&&) = default;
        json& operator=(const json&) = default;
        json& operator=(json&&) = default;

        template<typename T>
        json(const T& value) {
            // Simplified implementation
        }

        template<typename T>
        T get() const {
            // Simplified implementation
            return T();
        }

        template<typename T>
        T value(const std::string& key, const T& default_value) const {
            // Simplified implementation
            return default_value;
        }

        bool is_array() const { return false; }
        bool is_object() const { return false; }
        bool is_string() const { return false; }
        bool is_number() const { return false; }
        bool is_boolean() const { return false; }
        bool is_null() const { return false; }

        size_t size() const { return 0; }
        bool empty() const { return true; }

        json& operator[](const std::string& key) {
            return *this;
        }

        const json& operator[](const std::string& key) const {
            return *this;
        }

        json& operator[](size_t index) {
            return *this;
        }

        const json& operator[](size_t index) const {
            return *this;
        }

        void push_back(const json& value) {}
        void erase(const std::string& key) {}
        void clear() {}

        std::string dump(int indent = -1) const {
            return "{}";
        }
    };
} 