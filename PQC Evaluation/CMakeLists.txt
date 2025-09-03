cmake_minimum_required(VERSION 3.21)
project(pqc_demos C)

find_package(liboqs CONFIG REQUIRED)
find_package(OpenSSL REQUIRED) # needed by kyber.c AES-GCM; harmless for dilithium

# --- Kyber demo (already working) ---
add_executable(kyber kyber.c)
target_link_libraries(kyber PRIVATE OQS::oqs OpenSSL::Crypto)
target_compile_definitions(kyber PRIVATE TRACE_STEPS=1)
option(DUMP_SECRETS "Print secret material in hex (demo only!)" OFF)
if(DUMP_SECRETS)
  target_compile_definitions(kyber PRIVATE DUMP_SECRETS=1)
endif()

# --- Dilithium demo (new) ---
add_executable(dilithium dilithium.c)
target_link_libraries(dilithium PRIVATE OQS::oqs)
