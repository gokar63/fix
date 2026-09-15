cmake_minimum_required(VERSION 3.20)
project(Xeno LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Luau sources
file(GLOB LUAU_SRC "Luau/src/*.cpp")

# vcpkg handles xxhash and zstd automatically
find_package(xxHash CONFIG REQUIRED)
find_package(zstd CONFIG REQUIRED)

# Xeno Executor
add_executable(xeno main.cpp worker.cpp ntdll.cpp ${LUAU_SRC})
target_include_directories(xeno PRIVATE . Luau/include)
target_link_libraries(xeno PRIVATE
    xxHash::xxhash
    zstd::libzstd_static
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
