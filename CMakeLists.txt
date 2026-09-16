cmake_minimum_required(VERSION 3.20)
project(Xeno LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_definitions(-DNOMINMAX)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

include(FetchContent)

# Auto-download xxHash
FetchContent_Declare(xxhash
    GIT_REPOSITORY https://github.com/Cyan4973/xxHash.git
    GIT_TAG v0.8.2
    SOURCE_SUBDIR cmake_unofficial
)
set(XXHASH_BUILD_XXHSUM OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(xxhash)

# Auto-download zstd
FetchContent_Declare(zstd
    GIT_REPOSITORY https://github.com/facebook/zstd.git
    GIT_TAG v1.5.6
    SOURCE_SUBDIR build/cmake
)
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zstd)

# Auto-download ImGui (no CMakeLists.txt, we build it ourselves)
FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.91.6
)
FetchContent_GetProperties(imgui)
if(NOT imgui_POPULATED)
    FetchContent_Populate(imgui)
endif()

add_library(imgui_lib STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
)
target_include_directories(imgui_lib PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)
target_link_libraries(imgui_lib PUBLIC d3d11 dxgi)

# Luau sources
file(GLOB LUAU_SRC "Luau/src/*.cpp")

# VANTA Hack — all-in-one
add_executable(vanta_hack
    vanta_hack.cpp
    main.cpp worker.cpp ntdll.cpp
    ${LUAU_SRC}
)
target_include_directories(vanta_hack PRIVATE
    .
    Luau/include
    Luau/include/Luau
    Luau/src
)
target_link_libraries(vanta_hack PRIVATE
    xxhash
    libzstd_static
    psapi advapi32 ole32 oleaut32 uuid
    gdi32 dwmapi user32
)

# Offset Dumper
add_executable(offset_dumper offset_dumper.cpp)
target_link_libraries(offset_dumper PRIVATE psapi advapi32)

# VANTA DLL — internal hack (DX11 Present hook + ImGui)
add_library(vanta_dll SHARED vanta_dll.cpp)
target_link_libraries(vanta_dll PRIVATE imgui_lib user32 gdi32 d3d11 dxgi)

# Injector — manual map loader
add_executable(injector injector.cpp)
target_link_libraries(injector PRIVATE advapi32)

# VANTA External — overlay ESP (no injection, bypasses Byfron)
add_executable(vanta_external vanta_external.cpp)
target_link_libraries(vanta_external PRIVATE imgui_lib user32 gdi32 d3d11 dxgi dwmapi psapi advapi32)
