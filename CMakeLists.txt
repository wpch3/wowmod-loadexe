cmake_minimum_required(VERSION 3.16)
project(wowmod_loadexe LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WOWMOD_BUILD_TESTS "Build portable unit tests" ON)
option(WOWMOD_BUILD_HOOK_DLL "Build the injected Windows overlay DLL (Windows only)" ON)

set(WOWMOD_CORE_SOURCES
  src/core/util.cpp
  src/core/json.cpp
  src/core/version.cpp
  src/core/mapping.cpp
  src/core/config.cpp
  src/core/vfs.cpp
  src/core/hooks.cpp
)

add_library(wowmod_core STATIC ${WOWMOD_CORE_SOURCES})
target_include_directories(wowmod_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
if(MSVC)
  target_compile_options(wowmod_core PRIVATE /W3 /utf-8)
  target_compile_definitions(wowmod_core PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(wowmod_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ---- CLI ----
add_executable(wowmod src/cli/main.cpp)
target_link_libraries(wowmod PRIVATE wowmod_core)
target_include_directories(wowmod PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(WIN32)
  target_sources(wowmod PRIVATE src/windows/launch.cpp src/windows/inject.cpp)
  target_compile_definitions(wowmod PRIVATE UNICODE _UNICODE WOWMOD_WINDOWS)
  target_link_libraries(wowmod PRIVATE kernel32 user32 shell32)
else()
  target_sources(wowmod PRIVATE src/platform/launch_stub.cpp)
endif()

# ---- Injected overlay DLL (Windows) ----
if(WIN32 AND WOWMOD_BUILD_HOOK_DLL)
  add_library(wowmod_hook SHARED
    src/windows/runtime.cpp
    src/windows/overlay_dll.cpp
    src/windows/iat_hook.cpp
    src/windows/fs_hooks.cpp
    src/windows/fileid_hook.cpp
  )
  target_link_libraries(wowmod_hook PRIVATE wowmod_core)
  target_compile_definitions(wowmod_hook PRIVATE UNICODE _UNICODE WOWMOD_WINDOWS WOWMOD_HOOK_DLL)
  set_target_properties(wowmod_hook PROPERTIES OUTPUT_NAME "wowmod_hook")
endif()

# ---- Tests (portable, no third-party deps) ----
if(WOWMOD_BUILD_TESTS)
  enable_testing()
  add_executable(wowmod_tests tests/tests.cpp)
  target_link_libraries(wowmod_tests PRIVATE wowmod_core)
  add_test(NAME wowmod_tests COMMAND wowmod_tests)
endif()
