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

# Offset Dumper — run first to generate offsets
add_executable(offset_dumper offset_dumper.cpp)
target_link_libraries(offset_dumper PRIVATE psapi advapi32)

# VANTA DLL — internal hack (injected into Roblox)
add_library(vanta_dll SHARED vanta_dll.cpp)
target_link_libraries(vanta_dll PRIVATE user32 gdi32 psapi)

# Injector — loads vanta_dll.dll into Roblox
add_executable(injector injector.cpp)
target_link_libraries(injector PRIVATE advapi32)
