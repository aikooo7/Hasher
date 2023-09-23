cmake_minimum_required(VERSION 3.26)
project(Hasher C)

set(CMAKE_C_STANDARD 23)

find_package(OpenSSL REQUIRED)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")

add_executable(Hasher main.c)

install(TARGETS Hasher DESTINATION /usr/bin)

include_directories(Hasher PRIVATE ${OPENSSL_LIBRARIES})
target_link_libraries(Hasher PRIVATE ${OPENSSL_LIBRARIES})

