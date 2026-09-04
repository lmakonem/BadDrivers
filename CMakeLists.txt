cmake_minimum_required(VERSION 3.20)
project(BadDrivers LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows-only project
if(NOT WIN32)
    message(FATAL_ERROR "BadDrivers project requires Windows")
endif()

# Add include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# ============================================================================
# Target 1: byovd_sample2 - PPL disabling via BYOVD
# ============================================================================
add_executable(byovd_sample2
    samples/byovd_sample2.cpp
)

target_link_libraries(byovd_sample2
    ntdll.lib
    psapi.lib
)

# ============================================================================
# Target 2: dump_the_goodz - In-memory LSASS dump with XOR obfuscation
# ============================================================================
add_executable(dump_the_goodz
    samples/dump_the_goodz_7.cpp
)

target_link_libraries(dump_the_goodz
    ntdll.lib
    Dbghelp.lib
)

# ============================================================================
# Target 3: mock_driver_test - Mock PdFwKrnl driver for testing without hardware
# ============================================================================
add_executable(mock_driver_test
    src/mock_driver_test.cpp
)

target_link_libraries(mock_driver_test
    ntdll.lib
    psapi.lib
)

# ============================================================================
# Target 4: warp - our own single-binary BYOVD looter (strip PPL + dump + XOR)
# ============================================================================
add_executable(warp
    src/warp.cpp
)

target_link_libraries(warp
    ntdll.lib
    psapi.lib
    Dbghelp.lib
)

# ============================================================================
# Build Configuration (MSVC-specific)
# ============================================================================
if(MSVC)
    # Suppress specific warnings (inline asm, etc.)
    add_compile_options(/W4)

    # Link runtime statically for portability
    string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
    string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")

    # Add debug info to Release builds
    add_compile_options(/Zi)
    add_link_options(/DEBUG)
endif()

# ============================================================================
# Target 5: cascade - consolidated BYOVD (BiosToolCommonDriver + warp merge)
# ============================================================================
add_executable(cascade
    src/cascade.cpp
)

target_link_libraries(cascade
    ntdll.lib
    psapi.lib
    Dbghelp.lib
    advapi32.lib
)

# ============================================================================
# Install targets to bin/
# ============================================================================
install(TARGETS byovd_sample2 dump_the_goodz mock_driver_test warp cascade
    RUNTIME DESTINATION bin
)

# Copy findings and samples
install(FILES FINDINGS.md README.md CLAUDE.md AGENTS.md DESTINATION .)
install(DIRECTORY samples DESTINATION .)
