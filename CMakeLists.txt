cmake_minimum_required(VERSION 3.15)
project(inf2catExProject LANGUAGES CXX)

# Detours 源码路径
set(DETOURS_SRC
    detours/detours.cpp
    detours/disasm.cpp
    detours/modules.cpp
)
# 添加 Detours 头文件路径
include_directories(detours)
# 编译 detours 静态库
add_library(detours STATIC ${DETOURS_SRC})

# 添加可执行文件
add_executable(inf2catEx inf2catEx.cpp)

# 添加 DLL
add_library(HookFileTime SHARED HookFileTime.cpp)
target_link_libraries(HookFileTime PRIVATE detours)

# 设置输出文件名（可选）
set_target_properties(HookFileTime PROPERTIES OUTPUT_NAME "HookFileTime")
set_target_properties(inf2catEx PROPERTIES OUTPUT_NAME "inf2catEx")

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(inf2catEx PRIVATE _M_X64 DETOURS_X64)
    target_compile_definitions(HookFileTime PRIVATE _M_X64 DETOURS_X64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_compile_definitions(inf2catEx PRIVATE _M_IX86 DETOURS_X86)
    target_compile_definitions(HookFileTime PRIVATE _M_IX86 DETOURS_X86)
else()
    message(FATAL_ERROR "Unknown architecture")
endif()