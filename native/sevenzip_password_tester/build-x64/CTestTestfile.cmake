# CMake generated Testfile for 
# Source directory: C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester
# Build directory: C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester/build-x64
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test([=[sevenzip_password_tester_smoke]=] "C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester/build-x64/Debug/sevenzip_password_tester_smoke.exe")
  set_tests_properties([=[sevenzip_password_tester_smoke]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester/CMakeLists.txt;108;add_test;C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test([=[sevenzip_password_tester_smoke]=] "C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester/build-x64/Release/sevenzip_password_tester_smoke.exe")
  set_tests_properties([=[sevenzip_password_tester_smoke]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester/CMakeLists.txt;108;add_test;C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test([=[sevenzip_password_tester_smoke]=] "C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester/build-x64/MinSizeRel/sevenzip_password_tester_smoke.exe")
  set_tests_properties([=[sevenzip_password_tester_smoke]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester/CMakeLists.txt;108;add_test;C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test([=[sevenzip_password_tester_smoke]=] "C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester/build-x64/RelWithDebInfo/sevenzip_password_tester_smoke.exe")
  set_tests_properties([=[sevenzip_password_tester_smoke]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester/CMakeLists.txt;108;add_test;C:/Users/29402/Desktop/SUNPACK/smart_unpacker-2/native/sevenzip_password_tester/CMakeLists.txt;0;")
else()
  add_test([=[sevenzip_password_tester_smoke]=] NOT_AVAILABLE)
endif()
