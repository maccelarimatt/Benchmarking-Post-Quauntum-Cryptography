cmake_minimum_required(VERSION 3.21)
project(hello C)

find_package(liboqs CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(hello main.c)
target_link_libraries(hello PRIVATE OQS::oqs OpenSSL::Crypto)
