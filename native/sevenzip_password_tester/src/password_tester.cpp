#include "sevenzip_password_tester/password_tester.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

namespace smart_unpacker::sevenzip {

bool is_backend_available(const std::wstring& seven_zip_dll_path) {
#ifdef _WIN32
    HMODULE module = LoadLibraryW(seven_zip_dll_path.c_str());
    if (module == nullptr) {
        return false;
    }
    FreeLibrary(module);
    return true;
#else
    (void)seven_zip_dll_path;
    return false;
#endif
}

PasswordTestResult test_password(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::wstring& password
) {
    (void)archive_path;
    (void)password;

    PasswordTestResult result;
    result.backend_available = is_backend_available(seven_zip_dll_path);
    if (!result.backend_available) {
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "7z.dll could not be loaded";
        return result;
    }

    result.status = PasswordTestStatus::Unsupported;
    result.message = "7z.dll backend loaded; archive password testing is not wired yet";
    return result;
}

const char* status_name(PasswordTestStatus status) {
    switch (status) {
    case PasswordTestStatus::Ok:
        return "ok";
    case PasswordTestStatus::WrongPassword:
        return "wrong_password";
    case PasswordTestStatus::Damaged:
        return "damaged";
    case PasswordTestStatus::Unsupported:
        return "unsupported";
    case PasswordTestStatus::BackendUnavailable:
        return "backend_unavailable";
    case PasswordTestStatus::Error:
        return "error";
    }
    return "unknown";
}

}  // namespace smart_unpacker::sevenzip
