cmake_minimum_required(VERSION 3.20)
project(Xeno LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
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

# Xeno Executor
add_executable(xeno main.cpp worker.cpp ntdll.cpp ${LUAU_SRC})
target_include_directories(xeno PRIVATE . Luau/include)
target_link_libraries(xeno PRIVATE
    xxhash
    libzstd_static
    psapi advapi32 ole32 oleaut32 uuid
)

# ESP + Aimbot
add_executable(esp_aimbot esp_aimbot.cpp)
target_link_libraries(esp_aimbot PRIVATE gdi32 dwmapi psapi advapi32 user32)
set_target_properties(esp_aimbot PROPERTIES WIN32_EXECUTABLE TRUE)

# Aimbot
add_executable(aimbot aimbot.cpp)
target_link_libraries(aimbot PRIVATE gdi32 psapi advapi32 user32)

# Money Hack
add_executable(money_hack money_hack.cpp)
target_link_libraries(money_hack PRIVATE psapi advapi32)

# Dumper
add_executable(dumper dumper.cpp)
target_link_libraries(dumper PRIVATE psapi advapi32)
