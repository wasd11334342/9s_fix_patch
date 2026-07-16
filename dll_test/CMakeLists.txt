cmake_minimum_required(VERSION 3.20)
cmake_policy(SET CMP0091 NEW)
project(MyPatchDll LANGUAGES C CXX)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
add_compile_definitions(_WIN32_WINNT=0x0601 WINVER=0x0601)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
add_subdirectory(third_party/mbedtls EXCLUDE_FROM_ALL)

add_library(MyPatch SHARED
    dllmain.cpp
    license_tls_client.cpp
    license_tls_resources.rc)

target_compile_features(MyPatch PRIVATE cxx_std_17)
target_compile_options(MyPatch PRIVATE /utf-8)
target_link_libraries(MyPatch PRIVATE MbedTLS::mbedtls)
