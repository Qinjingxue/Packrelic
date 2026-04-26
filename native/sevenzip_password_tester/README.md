# sevenzip_password_tester

C++ scaffold for a future in-process `7z.dll` password-test backend.

This project currently proves that the local C++ toolchain can build and load
the bundled `7z.dll`. It intentionally does not replace Python's existing
`7z t` subprocess fallback yet.

## Build

```powershell
cmake -S native\sevenzip_password_tester -B native\sevenzip_password_tester\build
cmake --build native\sevenzip_password_tester\build --config Release
ctest --test-dir native\sevenzip_password_tester\build -C Release --output-on-failure
```

Run the smoke executable with the repository DLL:

```powershell
native\sevenzip_password_tester\build\Release\sevenzip_password_tester_smoke.exe tools\7z.dll
```

Expected status for now:

```text
backend_available=true
status=unsupported
```
