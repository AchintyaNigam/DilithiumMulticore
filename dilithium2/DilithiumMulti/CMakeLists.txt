# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.2.0)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.2.0-a4)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ------------------------------------------------------------------
# Pico SDK boilerplate
# ------------------------------------------------------------------
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()

set(PICO_BOARD pico2_w CACHE STRING "Board type")

include(pico_sdk_import.cmake)

project(dilithiummulti C CXX ASM)

pico_sdk_init()

# ------------------------------------------------------------------
# Build options
# ------------------------------------------------------------------
option(DILITHIUM_USE_AES "Use AES instead of SHAKE" OFF)
set(DILITHIUM_MODE 2 CACHE STRING "Dilithium security level (2,3,5)")

message(STATUS "Dilithium mode: ${DILITHIUM_MODE}")
message(STATUS "AES enabled: ${DILITHIUM_USE_AES}")

# ------------------------------------------------------------------
# Source groups
# ------------------------------------------------------------------
set(DILITHIUM_SOURCES
    sign.c
    packing.c
    polyvec.c
    poly.c
    ntt.c
    reduce.c
    rounding.c
)

# Select symmetric backend
if (DILITHIUM_USE_AES)
    set(SYMMETRIC_SOURCES
        aes256ctr.c
        symmetric-aes.c
        fips202.c
    )
else()
    set(SYMMETRIC_SOURCES
        fips202.c
        symmetric-shake.c
    )
endif()

# ------------------------------------------------------------------
# Executable target
# ------------------------------------------------------------------
add_executable(dilithiummulti
    MainTest.c
    ${DILITHIUM_SOURCES}
    ${SYMMETRIC_SOURCES}
    randombytes.c
)

# ------------------------------------------------------------------
# Target-specific compile options (CORRECT placement)
# ------------------------------------------------------------------
target_compile_options(dilithiummulti PRIVATE
    -Wall
    -Wextra
    -Wshadow
    -Wvla
    -Wpointer-arith
)

# ------------------------------------------------------------------
# Compile-time definitions
# ------------------------------------------------------------------
target_compile_definitions(dilithiummulti PRIVATE
    DILITHIUM_MODE=${DILITHIUM_MODE}
)

if (DILITHIUM_USE_AES)
    target_compile_definitions(dilithiummulti PRIVATE DILITHIUM_USE_AES)
endif()

# ------------------------------------------------------------------
# Pico libraries
# ------------------------------------------------------------------
target_link_libraries(dilithiummulti
    pico_stdlib
    pico_time
    pico_rand
    pico_cyw43_arch_none
)

pico_enable_stdio_usb(dilithiummulti 1)
pico_enable_stdio_uart(dilithiummulti 0)

# ------------------------------------------------------------------
# Outputs
# ------------------------------------------------------------------
pico_add_extra_outputs(dilithiummulti)
