cmake_minimum_required(VERSION 3.14)
project(kreamlink C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(APPLE)
    if(EXISTS "/opt/homebrew/opt/openssl@3")
        list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/openssl@3")
    elseif(EXISTS "/usr/local/opt/openssl@3")
        list(APPEND CMAKE_PREFIX_PATH "/usr/local/opt/openssl@3")
    endif()
    add_compile_definitions(_DARWIN_C_SOURCE)
else()
    add_compile_definitions(_POSIX_C_SOURCE=200809L _DEFAULT_SOURCE)
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(kreamlink
    src/main.c
    src/config.c
    src/control.c
    src/log.c
    src/crypto.c
    src/ws.c
    src/hub.c
    src/workers.c
    src/agent.c
)

target_include_directories(kreamlink PRIVATE include)
target_compile_options(kreamlink PRIVATE -Wall -Wextra -O2)
target_link_libraries(kreamlink PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

install(TARGETS kreamlink RUNTIME DESTINATION bin)
