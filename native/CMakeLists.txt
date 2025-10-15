cmake_minimum_required(VERSION 3.16)
project(pqcbench_native C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Build liboqs as a subproject with only the library target.
# Allow callers to opt-in to liboqs test/ACVP utilities when required.
option(PQCBENCH_ENABLE_LIBOQS_TESTS "Build liboqs test utilities (vectors_kem/sig)" OFF)

if(PQCBENCH_ENABLE_LIBOQS_TESTS)
    set(OQS_BUILD_ONLY_LIB OFF CACHE BOOL "" FORCE)
else()
    set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
endif()
set(OQS_DIST_BUILD OFF CACHE BOOL "" FORCE)
set(OQS_USE_CUPQC OFF CACHE BOOL "" FORCE)
set(OQS_USE_ICICLE OFF CACHE BOOL "" FORCE)

# Ensure desired algorithms are enabled in liboqs (particularly HQC)
# These options are consumed by liboqs when added as a subdirectory.
set(OQS_ENABLE_KEM_BIKE ON CACHE BOOL "Enable BIKE KEM in liboqs" FORCE)
set(OQS_ENABLE_KEM_bike_l1 ON CACHE BOOL "Enable BIKE-L1 KEM in liboqs" FORCE)
set(OQS_ENABLE_KEM_bike_l3 ON CACHE BOOL "Enable BIKE-L3 KEM in liboqs" FORCE)
set(OQS_ENABLE_KEM_bike_l5 ON CACHE BOOL "Enable BIKE-L5 KEM in liboqs" FORCE)
set(OQS_ENABLE_KEM_HQC ON CACHE BOOL "Enable HQC KEM in liboqs" FORCE)
set(OQS_ENABLE_KEM_NTRU ON CACHE BOOL "Enable NTRU KEM family in liboqs" FORCE)
set(OQS_ENABLE_KEM_ntru_hps2048509 ON CACHE BOOL "Enable NTRU-HPS-2048-509" FORCE)
set(OQS_ENABLE_KEM_ntru_hps2048677 ON CACHE BOOL "Enable NTRU-HPS-2048-677" FORCE)
set(OQS_ENABLE_KEM_ntru_hps4096821 ON CACHE BOOL "Enable NTRU-HPS-4096-821" FORCE)
set(OQS_ENABLE_KEM_ntru_hps40961229 ON CACHE BOOL "Enable NTRU-HPS-4096-1229" FORCE)
set(OQS_ENABLE_KEM_ntru_hrss701 ON CACHE BOOL "Enable NTRU-HRSS-701" FORCE)
set(OQS_ENABLE_KEM_ntru_hrss1373 ON CACHE BOOL "Enable NTRU-HRSS-1373" FORCE)
# Keep common NIST algorithms enabled (usually ON by default, but make explicit)
set(OQS_ENABLE_KEM_ML_KEM ON CACHE BOOL "Enable ML-KEM (Kyber) in liboqs" FORCE)
set(OQS_ENABLE_SIG_ML_DSA ON CACHE BOOL "Enable ML-DSA (Dilithium) in liboqs" FORCE)
set(OQS_ENABLE_SIG_FALCON ON CACHE BOOL "Enable Falcon in liboqs" FORCE)
set(OQS_ENABLE_SIG_SPHINCS ON CACHE BOOL "Enable SPHINCS+ in liboqs" FORCE)
# Enable SLH-DSA signature family (NIST LMS replacement)
set(OQS_ENABLE_SIG_SLH_DSA ON CACHE BOOL "Enable SLH-DSA signature family" FORCE)
set(OQS_ENABLE_SIG_slh_dsa_pure_sha2_128s ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_slh_dsa_pure_sha2_128f ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_slh_dsa_pure_sha2_192s ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_slh_dsa_pure_sha2_192f ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_slh_dsa_pure_sha2_256s ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_slh_dsa_pure_sha2_256f ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_slh_dsa_pure_shake_128s ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_slh_dsa_pure_shake_128f ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_slh_dsa_pure_shake_192s ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_slh_dsa_pure_shake_192f ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_slh_dsa_pure_shake_256s ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_slh_dsa_pure_shake_256f ON CACHE BOOL "" FORCE)
# Enable XMSS/XMSSMT (stateful) for analysis tooling via liboqs adapters
set(OQS_ENABLE_SIG_STFL_XMSS ON CACHE BOOL "Enable XMSS/XMSSMT signature family" FORCE)
set(OQS_ENABLE_SIG_STFL_xmss_sha256_h20 ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_STFL_xmssmt_sha256_h20_2 ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_STFL_xmssmt_sha256_h40_4 ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_STFL_xmssmt_sha256_h60_6 ON CACHE BOOL "" FORCE)
set(OQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN ON CACHE BOOL "" FORCE)

set(LIBOQS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../liboqs")
if(NOT EXISTS "${LIBOQS_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "liboqs source directory not found at ${LIBOQS_SOURCE_DIR}")
endif()

add_subdirectory(${LIBOQS_SOURCE_DIR} ${CMAKE_BINARY_DIR}/liboqs_build EXCLUDE_FROM_ALL)

find_package(OpenSSL COMPONENTS Crypto)

add_library(pqcbench_native SHARED
    src/pqcbench_native.c
)

target_include_directories(pqcbench_native
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${LIBOQS_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/liboqs_build/include
)

target_link_libraries(pqcbench_native
    PRIVATE
        oqs
)

if(OpenSSL_FOUND)
    target_link_libraries(pqcbench_native PRIVATE OpenSSL::Crypto)
    target_compile_definitions(pqcbench_native PRIVATE PQCBENCH_HAVE_OPENSSL)
else()
    message(STATUS "OpenSSL not found; RSA operations disabled in pqcbench_native.")
endif()

if(WIN32)
    target_compile_definitions(pqcbench_native PRIVATE PQCBENCH_NATIVE_EXPORTS)
endif()

install(TARGETS pqcbench_native
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(DIRECTORY include/ DESTINATION include)
