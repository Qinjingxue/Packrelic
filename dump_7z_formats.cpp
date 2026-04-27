#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

using UInt32 = std::uint32_t;

typedef int(WINAPI* GetNumberOfFormatsFunc)(UInt32* numFormats);
typedef int(WINAPI* GetHandlerProperty2Func)(UInt32 formatIndex, UInt32 propID, PROPVARIANT* value);

int main() {
    HMODULE dll = LoadLibraryA("tools/7z.dll");
    if (!dll) {
        std::cerr << "Failed to load tools/7z.dll\n";
        return 1;
    }
    auto GetNumberOfFormats = (GetNumberOfFormatsFunc)GetProcAddress(dll, "GetNumberOfFormats");
    auto GetHandlerProperty2 = (GetHandlerProperty2Func)GetProcAddress(dll, "GetHandlerProperty2");

    UInt32 num = 0;
    if (GetNumberOfFormats(&num) != 0) return 1;

    for (UInt32 i = 0; i < num; ++i) {
        PROPVARIANT propName{};
        if (GetHandlerProperty2(i, 0, &propName) == 0 && propName.vt == VT_BSTR) {
            std::wcout << propName.bstrVal << L": ";
            SysFreeString(propName.bstrVal);
        }

        PROPVARIANT propClsid{};
        if (GetHandlerProperty2(i, 1, &propClsid) == 0) {
            if (propClsid.vt == 72) { // VT_CLSID? Wait, VT_CLSID is not 72? Actually PROPVARIANT for CLSID might be VT_BSTR or VT_BLOB or something. Let's just cast data to byte array.
                 // Actually PROPVARIANT uses 'puuid'
            }
        }
        
        // Just print the whole byte array for the guid!
        PROPVARIANT p2{};
        if (GetHandlerProperty2(i, 1, &p2) == 0) {
            unsigned char* guid_ptr = (unsigned char*)(p2.puuid); // actually puuid is inside unions. 
            // VT_BSTR contains pointer. Let's just cast p2 to an array of bytes and find the pointer.
            if (p2.vt == 72) {
                unsigned char* p = *(unsigned char**)(&p2.decVal); // VT_CLSID
                printf("%02X ", p[13]);
            }
        }
        printf("\n");
    }
    return 0;
}
