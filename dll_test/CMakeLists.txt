cmake_minimum_required(VERSION 3.20)
project(MyPatchDll LANGUAGES CXX)

add_library(MyPatch SHARED dllmain.cpp)

target_compile_features(MyPatch PRIVATE cxx_std_17)
target_compile_options(MyPatch PRIVATE /utf-8)
target_link_libraries(MyPatch PRIVATE winhttp)
