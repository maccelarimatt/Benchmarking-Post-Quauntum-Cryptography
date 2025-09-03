cmake_minimum_required(VERSION 3.21)
project(kyber_demo C)

find_package(liboqs CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(kyber kyber.c)  # <-- match the actual file name
target_link_libraries(kyber PRIVATE OQS::oqs OpenSSL::Crypto)

# Step banners always on
target_compile_definitions(kyber PRIVATE TRACE_STEPS=1)

# Optional: dump secret material (OFF by default)
option(DUMP_SECRETS "Print secret material in hex" OFF)
if(DUMP_SECRETS)
  target_compile_definitions(kyber PRIVATE DUMP_SECRETS=1)
endif()
