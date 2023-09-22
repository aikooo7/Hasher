cmake_minimum_required(VERSION 3.26)
project(C_cryptograph_file C)

set(CMAKE_C_STANDARD 23)

find_package(OpenSSL REQUIRED)

add_executable(C_cryptograph_file main.c)
set_target_properties(C_cryptograph_file PROPERTIES OUTPUT_NAME "Hasher")

include_directories(C_cryptograph_file PRIVATE ${OPENSSL_LIBRARIES})
target_link_libraries(C_cryptograph_file PRIVATE ${OPENSSL_LIBRARIES})
