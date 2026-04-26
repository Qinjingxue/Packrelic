#include "sevenzip_password_tester/password_tester.hpp"

#ifdef _WIN32
#include <objbase.h>
#include <oleauto.h>
#include <windows.h>
#endif

#include <algorithm>
#include <cstdint>
#include <cwchar>
#include <filesystem>
#include <string>
#include <vector>

namespace smart_unpacker::sevenzip {

#ifdef _WIN32

using UInt32 = std::uint32_t;
using UInt64 = std::uint64_t;
using Int32 = std::int32_t;
using Int64 = std::int64_t;

constexpr Int32 kAllItems = -1;
constexpr Int32 kTestMode = 1;

constexpr Int32 kOpOk = 0;
constexpr Int32 kOpUnsupportedMethod = 1;
constexpr Int32 kOpDataError = 2;
constexpr Int32 kOpCrcError = 3;
constexpr Int32 kOpUnavailable = 4;
constexpr Int32 kOpUnexpectedEnd = 5;
constexpr Int32 kOpDataAfterEnd = 6;
constexpr Int32 kOpIsNotArc = 7;
constexpr Int32 kOpHeadersError = 8;
constexpr Int32 kOpWrongPassword = 9;

const GUID IID_ISequentialInStream = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00}};
const GUID IID_IInStream = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00}};
const GUID IID_IProgress = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00}};
const GUID IID_ICryptoGetTextPassword = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x05, 0x00, 0x10, 0x00, 0x00}};
const GUID IID_IArchiveOpenCallback = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x06, 0x00, 0x10, 0x00, 0x00}};
const GUID IID_IArchiveExtractCallback = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x06, 0x00, 0x20, 0x00, 0x00}};
const GUID IID_IInArchive = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x06, 0x00, 0x60, 0x00, 0x00}};

GUID format_guid(unsigned char format_id) {
    return {0x23170F69, 0x40C1, 0x278A, {0x10, 0x00, 0x00, 0x01, 0x10, format_id, 0x00, 0x00}};
}

struct ISequentialInStream : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Read(void* data, UInt32 size, UInt32* processedSize) = 0;
};

struct IInStream : public ISequentialInStream {
    virtual HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64* newPosition) = 0;
};

struct IProgress : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE SetTotal(UInt64 total) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64* completeValue) = 0;
};

struct IArchiveOpenCallback : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE SetTotal(const UInt64* files, const UInt64* bytes) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64* files, const UInt64* bytes) = 0;
};

struct ISequentialOutStream : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Write(const void* data, UInt32 size, UInt32* processedSize) = 0;
};

struct IArchiveExtractCallback : public IProgress {
    virtual HRESULT STDMETHODCALLTYPE GetStream(UInt32 index, ISequentialOutStream** outStream, Int32 askExtractMode) = 0;
    virtual HRESULT STDMETHODCALLTYPE PrepareOperation(Int32 askExtractMode) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetOperationResult(Int32 opRes) = 0;
};

struct ICryptoGetTextPassword : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR* password) = 0;
};

struct IInArchive : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Open(IInStream* stream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* openCallback) = 0;
    virtual HRESULT STDMETHODCALLTYPE Close() = 0;
    virtual HRESULT STDMETHODCALLTYPE GetNumberOfItems(UInt32* numItems) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetProperty(UInt32 index, UInt32 propID, PROPVARIANT* value) = 0;
    virtual HRESULT STDMETHODCALLTYPE Extract(const UInt32* indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback* extractCallback) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetArchiveProperty(UInt32 propID, PROPVARIANT* value) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetNumberOfProperties(UInt32* numProps) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetPropertyInfo(UInt32 index, BSTR* name, UInt32* propID, VARTYPE* varType) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetNumberOfArchiveProperties(UInt32* numProps) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetArchivePropertyInfo(UInt32 index, BSTR* name, UInt32* propID, VARTYPE* varType) = 0;
};

using CreateObjectFunc = HRESULT(WINAPI*)(const GUID* clsid, const GUID* iid, void** outObject);

class ComModule {
public:
    explicit ComModule(const std::wstring& path) : module_(LoadLibraryW(path.c_str())) {}
    ~ComModule() {
        if (module_) {
            FreeLibrary(module_);
        }
    }
    HMODULE get() const { return module_; }
    CreateObjectFunc create_object() const {
        if (!module_) {
            return nullptr;
        }
        return reinterpret_cast<CreateObjectFunc>(GetProcAddress(module_, "CreateObject"));
    }

private:
    HMODULE module_ = nullptr;
};

template <typename T>
class ComPtr {
public:
    ComPtr() = default;
    explicit ComPtr(T* ptr) : ptr_(ptr) {}
    ~ComPtr() { reset(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    T* get() const { return ptr_; }
    T** out() {
        reset();
        return &ptr_;
    }
    T* operator->() const { return ptr_; }
    explicit operator bool() const { return ptr_ != nullptr; }
    void reset() {
        if (ptr_) {
            ptr_->Release();
            ptr_ = nullptr;
        }
    }

private:
    T* ptr_ = nullptr;
};

class FileInStream final : public IInStream {
public:
    explicit FileInStream(const std::wstring& path)
        : handle_(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) {}
    ~FileInStream() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }
    bool is_open() const { return handle_ != INVALID_HANDLE_VALUE; }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
        if (!object) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_ISequentialInStream) || IsEqualGUID(iid, IID_IInStream)) {
            *object = static_cast<IInStream*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG refs = InterlockedDecrement(&refs_);
        if (refs == 0) {
            delete this;
        }
        return refs;
    }
    HRESULT STDMETHODCALLTYPE Read(void* data, UInt32 size, UInt32* processedSize) override {
        if (processedSize) {
            *processedSize = 0;
        }
        DWORD read = 0;
        if (!ReadFile(handle_, data, size, &read, nullptr)) {
            return HRESULT_FROM_WIN32(GetLastError());
        }
        if (processedSize) {
            *processedSize = read;
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64* newPosition) override {
        LARGE_INTEGER distance{};
        distance.QuadPart = offset;
        LARGE_INTEGER new_pos{};
        if (!SetFilePointerEx(handle_, distance, &new_pos, seekOrigin)) {
            return HRESULT_FROM_WIN32(GetLastError());
        }
        if (newPosition) {
            *newPosition = static_cast<UInt64>(new_pos.QuadPart);
        }
        return S_OK;
    }

private:
    LONG refs_ = 1;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

class OpenCallback final : public IArchiveOpenCallback, public ICryptoGetTextPassword {
public:
    explicit OpenCallback(std::wstring password) : password_(std::move(password)) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
        if (!object) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_IArchiveOpenCallback)) {
            *object = static_cast<IArchiveOpenCallback*>(this);
        } else if (IsEqualGUID(iid, IID_ICryptoGetTextPassword)) {
            *object = static_cast<ICryptoGetTextPassword*>(this);
        } else {
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG refs = InterlockedDecrement(&refs_);
        if (refs == 0) {
            delete this;
        }
        return refs;
    }
    HRESULT STDMETHODCALLTYPE SetTotal(const UInt64*, const UInt64*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64*, const UInt64*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR* password) override {
        if (!password) {
            return E_POINTER;
        }
        *password = SysAllocString(password_.c_str());
        return *password ? S_OK : E_OUTOFMEMORY;
    }

private:
    LONG refs_ = 1;
    std::wstring password_;
};

class ExtractCallback final : public IArchiveExtractCallback, public ICryptoGetTextPassword {
public:
    explicit ExtractCallback(std::wstring password) : password_(std::move(password)) {}
    Int32 operation_result() const { return operation_result_; }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
        if (!object) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_IProgress) || IsEqualGUID(iid, IID_IArchiveExtractCallback)) {
            *object = static_cast<IArchiveExtractCallback*>(this);
        } else if (IsEqualGUID(iid, IID_ICryptoGetTextPassword)) {
            *object = static_cast<ICryptoGetTextPassword*>(this);
        } else {
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG refs = InterlockedDecrement(&refs_);
        if (refs == 0) {
            delete this;
        }
        return refs;
    }
    HRESULT STDMETHODCALLTYPE SetTotal(UInt64) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetStream(UInt32, ISequentialOutStream** outStream, Int32) override {
        if (!outStream) {
            return E_POINTER;
        }
        *outStream = nullptr;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PrepareOperation(Int32) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetOperationResult(Int32 opRes) override {
        operation_result_ = opRes;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR* password) override {
        if (!password) {
            return E_POINTER;
        }
        *password = SysAllocString(password_.c_str());
        return *password ? S_OK : E_OUTOFMEMORY;
    }

private:
    LONG refs_ = 1;
    std::wstring password_;
    Int32 operation_result_ = kOpOk;
};

std::wstring lower_extension(const std::wstring& path) {
    std::wstring ext = std::filesystem::path(path).extension().wstring();
    std::transform(ext.begin(), ext.end(), ext.begin(), [](wchar_t ch) { return static_cast<wchar_t>(::towlower(ch)); });
    return ext;
}

std::vector<GUID> candidate_formats(const std::wstring& archive_path) {
    const std::wstring ext = lower_extension(archive_path);
    std::vector<unsigned char> ids;
    if (ext == L".zip" || ext == L".jar" || ext == L".docx" || ext == L".xlsx" || ext == L".apk") {
        ids = {0x01};
    } else if (ext == L".7z" || ext == L".001") {
        ids = {0x07};
    } else if (ext == L".rar" || ext == L".r00") {
        ids = {0x03, 0xCC};
    } else {
        ids = {0x07, 0x01, 0x03, 0xCC};
    }

    std::vector<GUID> formats;
    for (const unsigned char id : ids) {
        formats.push_back(format_guid(id));
    }
    return formats;
}

bool looks_wrong_password(HRESULT hr, Int32 op_res) {
    return op_res == kOpWrongPassword || op_res == kOpDataError || op_res == kOpCrcError || hr == S_FALSE;
}

bool looks_damaged(Int32 op_res) {
    return op_res == kOpUnexpectedEnd || op_res == kOpHeadersError || op_res == kOpIsNotArc || op_res == kOpUnavailable;
}

PasswordTestResult test_one_password(
    CreateObjectFunc create_object,
    const std::wstring& archive_path,
    const std::wstring& password
) {
    PasswordTestResult result;
    result.backend_available = true;

    bool any_format_created = false;
    bool any_opened = false;
    HRESULT last_hr = E_FAIL;
    Int32 last_op_res = kOpOk;

    for (const GUID& format : candidate_formats(archive_path)) {
        ComPtr<IInArchive> archive;
        HRESULT hr = create_object(&format, &IID_IInArchive, reinterpret_cast<void**>(archive.out()));
        if (hr != S_OK || !archive) {
            last_hr = hr;
            continue;
        }
        any_format_created = true;

        ComPtr<IInStream> stream(new FileInStream(archive_path));
        auto* file_stream = static_cast<FileInStream*>(stream.get());
        if (!file_stream->is_open()) {
            result.status = PasswordTestStatus::Error;
            result.message = "archive file could not be opened";
            return result;
        }

        ComPtr<IArchiveOpenCallback> open_callback(new OpenCallback(password));
        hr = archive->Open(stream.get(), nullptr, open_callback.get());
        if (hr != S_OK) {
            last_hr = hr;
            continue;
        }
        any_opened = true;

        auto* raw_extract_callback = new ExtractCallback(password);
        ComPtr<IArchiveExtractCallback> extract_callback(raw_extract_callback);
        hr = archive->Extract(nullptr, static_cast<UInt32>(kAllItems), kTestMode, extract_callback.get());
        last_hr = hr;
        last_op_res = raw_extract_callback->operation_result();
        archive->Close();

        if (hr == S_OK && last_op_res == kOpOk) {
            result.status = PasswordTestStatus::Ok;
            result.message = "password accepted";
            return result;
        }

        if (looks_wrong_password(hr, last_op_res)) {
            result.status = PasswordTestStatus::WrongPassword;
            result.message = "wrong password";
            return result;
        }

        if (looks_damaged(last_op_res)) {
            result.status = PasswordTestStatus::Damaged;
            result.message = "archive appears damaged";
            return result;
        }
    }

    if (!any_format_created) {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "7z.dll did not create a supported archive handler";
    } else if (!any_opened) {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "archive could not be opened by supported handlers";
    } else if (looks_damaged(last_op_res)) {
        result.status = PasswordTestStatus::Damaged;
        result.message = "archive appears damaged";
    } else if (looks_wrong_password(last_hr, last_op_res)) {
        result.status = PasswordTestStatus::WrongPassword;
        result.message = "wrong password";
    } else {
        result.status = PasswordTestStatus::Error;
        result.message = "archive test failed";
    }
    return result;
}

#endif

bool is_backend_available(const std::wstring& seven_zip_dll_path) {
#ifdef _WIN32
    ComModule module(seven_zip_dll_path);
    return module.get() != nullptr && module.create_object() != nullptr;
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
#ifdef _WIN32
    ComModule module(seven_zip_dll_path);
    CreateObjectFunc create_object = module.create_object();
    if (!create_object) {
        PasswordTestResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "7z.dll could not be loaded";
        return result;
    }

    PasswordTestResult result = test_one_password(create_object, archive_path, password);
    result.attempts = 1;
    result.matched_index = result.status == PasswordTestStatus::Ok ? 0 : -1;
    return result;
#else
    (void)seven_zip_dll_path;
    (void)archive_path;
    (void)password;
    PasswordTestResult result;
    result.status = PasswordTestStatus::BackendUnavailable;
    result.message = "native password testing is only implemented on Windows";
    return result;
#endif
}

PasswordTestResult test_passwords(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const wchar_t* const* passwords,
    int password_count
) {
#ifdef _WIN32
    ComModule module(seven_zip_dll_path);
    CreateObjectFunc create_object = module.create_object();
    if (!create_object) {
        PasswordTestResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "7z.dll could not be loaded";
        return result;
    }

    PasswordTestResult last;
    last.backend_available = true;
    if (password_count <= 0) {
        const wchar_t* empty = L"";
        passwords = &empty;
        password_count = 1;
    }
    const std::wstring ext = lower_extension(archive_path);
    const bool retry_unsupported_as_password = ext == L".7z" || ext == L".001";

    for (int i = 0; i < password_count; ++i) {
        const wchar_t* raw_password = passwords[i] ? passwords[i] : L"";
        PasswordTestResult current = test_one_password(create_object, archive_path, raw_password);
        current.attempts = i + 1;
        last = current;
        if (current.status == PasswordTestStatus::Ok) {
            current.matched_index = i;
            return current;
        }
        if (current.status == PasswordTestStatus::BackendUnavailable ||
            current.status == PasswordTestStatus::Damaged ||
            current.status == PasswordTestStatus::Error) {
            current.matched_index = -1;
            return current;
        }
        if (current.status == PasswordTestStatus::Unsupported && !retry_unsupported_as_password) {
            current.matched_index = -1;
            return current;
        }
    }

    last.status = PasswordTestStatus::WrongPassword;
    last.matched_index = -1;
    last.attempts = password_count;
    last.message = "wrong password";
    return last;
#else
    (void)seven_zip_dll_path;
    (void)archive_path;
    (void)passwords;
    (void)password_count;
    PasswordTestResult result;
    result.status = PasswordTestStatus::BackendUnavailable;
    result.message = "native password testing is only implemented on Windows";
    return result;
#endif
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

#ifdef _WIN32
namespace {

void copy_message(wchar_t* destination, int destination_chars, const std::string& message) {
    if (!destination || destination_chars <= 0) {
        return;
    }
    std::wstring wide(message.begin(), message.end());
    const int count = static_cast<int>(std::min<std::size_t>(wide.size(), static_cast<std::size_t>(destination_chars - 1)));
    std::wmemcpy(destination, wide.c_str(), count);
    destination[count] = L'\0';
}

int status_code(smart_unpacker::sevenzip::PasswordTestStatus status) {
    return static_cast<int>(status);
}

}  // namespace

SUP7Z_API int sup7z_try_passwords(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* passwords,
    int password_count,
    int* matched_index,
    int* attempts,
    wchar_t* message,
    int message_chars
) {
    if (matched_index) {
        *matched_index = -1;
    }
    if (attempts) {
        *attempts = 0;
    }
    if (!seven_zip_dll_path || !archive_path) {
        copy_message(message, message_chars, "missing required path");
        return status_code(smart_unpacker::sevenzip::PasswordTestStatus::Error);
    }

    const auto result = smart_unpacker::sevenzip::test_passwords(
        seven_zip_dll_path,
        archive_path,
        passwords,
        password_count);
    if (matched_index) {
        *matched_index = result.matched_index;
    }
    if (attempts) {
        *attempts = result.attempts;
    }
    copy_message(message, message_chars, result.message);
    return status_code(result.status);
}
#endif
