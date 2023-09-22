cmake_minimum_required(VERSION 3.26)
project(Hasher C)

set(CMAKE_C_STANDARD 23)

find_package(OpenSSL REQUIRED)

add_executable(Hasher main.c)

include_directories(Hasher PRIVATE ${OPENSSL_LIBRARIES})
target_link_libraries(Hasher PRIVATE ${OPENSSL_LIBRARIES})
