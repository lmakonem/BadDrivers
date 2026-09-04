# CMakeLists.txt — MSVC (Visual Studio 2022) native build for BadDrivers.
#
# Cross-platform note: cascade.cpp / warp.cpp / mock_driver_test.cpp target
# Windows only. For MinGW cross-compile from macOS or Linux, use
# `scripts/build.sh` instead — it produces identical binaries with a smaller
# footprint and no MSVC runtime dependency.
#
# Usage (Windows / Developer Command Prompt for VS 2022):
#   mkdir build && cd build
#   cmake .. -G "Visual Studio 17 2022" -A x64
#   cmake --build . --config Release
#
# Output:
#   build/Release/cascade.exe
#   build/Release/warp.exe
#   build/Release/mock_driver_test.exe

cmake_minimum_required(VERSION 3.15)
project(BadDrivers CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR "BadDrivers targets Windows only. Use MinGW cross-compile "
                        "(scripts/build.sh) from non-Windows hosts.")
endif()

# Static CRT (no msvcp*.dll runtime dep)
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/W3 /O2 /Zi /EHsc)
    add_link_options(/DEBUG:NONE)
endif()

# ---- cascade.exe: primary payload -------------------------------------------
add_executable(cascade src/cascade.cpp)
target_link_libraries(cascade PRIVATE
    ws2_32
    ntdll
    dbghelp
    psapi
    advapi32
    crypt32
)
set_target_properties(cascade PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Release
)

# ---- warp.exe: legacy PdFwKrnl-only PPL strip + dump ------------------------
add_executable(warp src/warp.cpp)
target_link_libraries(warp PRIVATE
    dbghelp
    psapi
    advapi32
)
set_target_properties(warp PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Release
)

# ---- mock_driver_test.exe: offline offset validator (CI-friendly) -----------
add_executable(mock_driver_test src/mock_driver_test.cpp)
set_target_properties(mock_driver_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Release
)

# ---- Samples (reference implementations, opt-in) ----------------------------
option(BUILD_SAMPLES "Build archival sample binaries" OFF)
if(BUILD_SAMPLES)
    add_executable(byovd_sample2   samples/byovd_sample2.cpp)
    target_link_libraries(byovd_sample2 PRIVATE psapi ntdll)
    add_executable(dump_the_goodz  samples/dump_the_goodz_7.cpp)
    target_link_libraries(dump_the_goodz PRIVATE dbghelp)
endif()

# ---- Test registration ------------------------------------------------------
enable_testing()
add_test(NAME mock_offsets COMMAND mock_driver_test)

message(STATUS "BadDrivers configured. Targets:")
message(STATUS "  cascade              (primary BYOVD binary)")
message(STATUS "  warp                 (legacy PdFwKrnl PPL+dump)")
message(STATUS "  mock_driver_test     (offline offset validator)")
if(BUILD_SAMPLES)
    message(STATUS "  byovd_sample2, dump_the_goodz  (BUILD_SAMPLES=ON)")
endif()
