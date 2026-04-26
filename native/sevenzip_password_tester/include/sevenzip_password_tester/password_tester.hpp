#pragma once

#include <string>

namespace smart_unpacker::sevenzip {

enum class PasswordTestStatus {
    Ok,
    WrongPassword,
    Damaged,
    Unsupported,
    BackendUnavailable,
    Error,
};

struct PasswordTestResult {
    PasswordTestStatus status = PasswordTestStatus::BackendUnavailable;
    bool backend_available = false;
    std::string message;
};

bool is_backend_available(const std::wstring& seven_zip_dll_path);

PasswordTestResult test_password(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::wstring& password
);

const char* status_name(PasswordTestStatus status);

}  // namespace smart_unpacker::sevenzip
