# Copyright 2024
#
# This file is part of gr-linux-crypto
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

cmake_minimum_required(VERSION 3.16)
if(POLICY CMP0057)
    cmake_policy(SET CMP0057 NEW)
endif()

project(gr-linux-crypto)

########################################################################
# Find dependencies
########################################################################
# Set CMAKE_MODULE_PATH to find GNU Radio CMake modules
# Search in common installation locations
list(APPEND CMAKE_MODULE_PATH
    /usr/local/lib/cmake/gnuradio
    /usr/lib/x86_64-linux-gnu/cmake/gnuradio
    /usr/lib/cmake/gnuradio
    ${CMAKE_INSTALL_PREFIX}/lib/cmake/gnuradio
)
include(GrBoost)

# Required dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(KEYUTILS REQUIRED libkeyutils)

# OpenSSL (modern imported target)
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    if(NOT TARGET OpenSSL::Crypto)
        message(WARNING "OpenSSL found but OpenSSL::Crypto target is missing; OpenSSL support disabled")
        set(OpenSSL_FOUND FALSE)
    endif()
endif()

# libsodium: prefer /usr/local (e.g. 1.0.22) over older distro headers in /usr/include
set(_SODIUM_PKG_PC_DIR "/usr/local/lib/pkgconfig")
if(DEFINED ENV{PKG_CONFIG_PATH} AND NOT "$ENV{PKG_CONFIG_PATH}" STREQUAL "")
    set(ENV{PKG_CONFIG_PATH} "${_SODIUM_PKG_PC_DIR}:$ENV{PKG_CONFIG_PATH}")
else()
    set(ENV{PKG_CONFIG_PATH} "${_SODIUM_PKG_PC_DIR}")
endif()
pkg_check_modules(SODIUM QUIET IMPORTED_TARGET libsodium)
set(LIBSODIUM_VERSION_REPORT "")
if(SODIUM_FOUND)
    set(LIBSODIUM_VERSION_REPORT "${SODIUM_VERSION}")
    if(TARGET PkgConfig::SODIUM AND NOT TARGET sodium::sodium)
        add_library(sodium::sodium ALIAS PkgConfig::SODIUM)
    endif()
else()
    find_library(SODIUM_LIBRARY
        NAMES sodium
        PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu
        NO_DEFAULT_PATH
    )
    find_path(SODIUM_INCLUDE_DIR
        NAMES sodium.h
        PATHS /usr/local/include /usr/include
        NO_DEFAULT_PATH
    )
    if(SODIUM_LIBRARY AND SODIUM_INCLUDE_DIR)
        set(SODIUM_FOUND TRUE)
        add_library(sodium::sodium UNKNOWN IMPORTED)
        set_target_properties(sodium::sodium PROPERTIES
            IMPORTED_LOCATION "${SODIUM_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
        )
        if(EXISTS "${SODIUM_INCLUDE_DIR}/sodium/version.h")
            file(STRINGS "${SODIUM_INCLUDE_DIR}/sodium/version.h" _SODIUM_VER_LINE
                REGEX "^#define[ \t]+SODIUM_VERSION_STRING")
            if(_SODIUM_VER_LINE)
                string(REGEX REPLACE ".*\"([^\"]+)\".*" "\\1" LIBSODIUM_VERSION_REPORT "${_SODIUM_VER_LINE}")
            endif()
        endif()
        if(NOT LIBSODIUM_VERSION_REPORT)
            set(LIBSODIUM_VERSION_REPORT "unknown (manual find)")
        endif()
    endif()
endif()
if(SODIUM_FOUND AND NOT LIBSODIUM_VERSION_REPORT)
    set(LIBSODIUM_VERSION_REPORT "${SODIUM_VERSION}")
endif()

# Optional GPGME support for OpenPGP Card operations
pkg_check_modules(GPGME QUIET gpgme)

# Optional hardware security module support (silent when absent)
pkg_check_modules(NITROKEY QUIET libnitrokey-1 libnitrokey)

########################################################################
# Register component
########################################################################
# Find GNU Radio via pkg-config first (sets ENABLE_GNURADIO_RUNTIME)
pkg_check_modules(GNURADIO_RUNTIME REQUIRED gnuradio-runtime)
if(GNURADIO_RUNTIME_FOUND)
    set(ENABLE_GNURADIO_RUNTIME ON)
    # Check for minimum GNU Radio version (3.10.12.0 or later)
    # This check ensures compatibility while allowing future versions
    set(GNURADIO_MIN_VERSION "3.10.12.0")
    if(DEFINED GNURADIO_RUNTIME_VERSION)
        if(GNURADIO_RUNTIME_VERSION VERSION_LESS GNURADIO_MIN_VERSION)
            message(FATAL_ERROR "GNU Radio version ${GNURADIO_MIN_VERSION} or later is required. Found: ${GNURADIO_RUNTIME_VERSION}")
        else()
            # Log version for compatibility tracking
            message(STATUS "GNU Radio version: ${GNURADIO_RUNTIME_VERSION} (minimum required: ${GNURADIO_MIN_VERSION})")
        endif()
    else()
        message(WARNING "GNU Radio version could not be determined. Please ensure GNU Radio ${GNURADIO_MIN_VERSION} or later is installed.")
    endif()
endif()

include(GrComponent)
gr_register_component("gr-linux-crypto" ENABLE_GR_LINUX_CRYPTO KEYUTILS_FOUND ENABLE_GNURADIO_RUNTIME)

########################################################################
# Build options
########################################################################
option(ENABLE_PYTHON "Enable Python bindings" ON)
option(ENABLE_GRC "Enable GRC block definitions" ON)
option(ENABLE_EXAMPLES "Install example scripts" ON)
option(ENABLE_DOXYGEN "Build Doxygen documentation" OFF)
option(ENABLE_TESTING "Enable testing" OFF)
option(ENABLE_FUZZING "Enable fuzzing targets" OFF)

# Optional components (each independent, default OFF)
option(GR_LINUX_CRYPTO_FIPS "Enable OpenSSL FIPS 140-3 provider mode" OFF)
option(GR_LINUX_CRYPTO_PQ_KEM "Enable post-quantum hybrid KEM (Brainpool + FrodoKEM)" OFF)
option(GR_LINUX_CRYPTO_SBOM "Enable SBOM generation (CycloneDX + SPDX)" OFF)
option(GR_LINUX_CRYPTO_STRICT_BSI "Enforce BSI TR-02102 algorithm boundary (EUCC/BSZ)" OFF)

if(GR_LINUX_CRYPTO_FIPS AND NOT OpenSSL_FOUND)
    message(FATAL_ERROR "GR_LINUX_CRYPTO_FIPS requires OpenSSL. Enable OpenSSL or set GR_LINUX_CRYPTO_FIPS=OFF.")
endif()

########################################################################
# Begin conditional configuration
########################################################################
if(ENABLE_GR_LINUX_CRYPTO)

########################################################################
# Compiler setup
########################################################################
if(CMAKE_COMPILER_IS_GNUCXX AND NOT WIN32)
    add_definitions(-fvisibility=hidden)
endif()

########################################################################
# Include directories
########################################################################
include_directories(${CMAKE_SOURCE_DIR}/lib)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${GNURADIO_INCLUDE_DIRS})

########################################################################
# API definition
# Note: LINUX_CRYPTO_API is defined in include/gnuradio/linux_crypto/api.h
# using GNU Radio's standard __GR_ATTR_EXPORT/__GR_ATTR_IMPORT macros

########################################################################
# Library sources
########################################################################
set(gr_linux_crypto_sources
    lib/kernel_keyring_source_impl.cc
    lib/nitrokey_interface_impl.cc
    lib/kernel_crypto_aes_impl.cc
    lib/openpgp_card_helper.cc
    lib/fips_guard.cc
    lib/bsi_boundary.cc
)

if(OpenSSL_FOUND)
    list(APPEND gr_linux_crypto_sources
        lib/brainpool_ec_impl.cc
        lib/brainpool_ecies_encrypt_impl.cc
        lib/brainpool_ecies_decrypt_impl.cc
        lib/brainpool_ecies_multi_encrypt_impl.cc
        lib/brainpool_ecies_multi_decrypt_impl.cc
        lib/brainpool_ecdsa_sign_impl.cc
        lib/brainpool_ecdsa_verify_impl.cc
    )
endif()

if(SODIUM_FOUND)
    list(APPEND gr_linux_crypto_sources
        lib/kem_encrypt_impl.cc
        lib/kem_decrypt_impl.cc
        lib/kem_generate_keypair_impl.cc
        lib/hash_sha3_impl.cc
    )
endif()

set(gr_linux_crypto_headers
    lib/kernel_keyring_source_impl.h
    lib/openpgp_card_helper.h
    lib/nitrokey_interface_impl.h
    lib/kernel_crypto_aes_impl.h
)

if(OpenSSL_FOUND)
    list(APPEND gr_linux_crypto_headers
        lib/brainpool_ec_impl.h
        lib/brainpool_ecies_encrypt_impl.h
        lib/brainpool_ecies_decrypt_impl.h
        lib/brainpool_ecies_multi_encrypt_impl.h
        lib/brainpool_ecies_multi_decrypt_impl.h
        lib/brainpool_ecdsa_sign_impl.h
        lib/brainpool_ecdsa_verify_impl.h
    )
endif()

if(SODIUM_FOUND)
    list(APPEND gr_linux_crypto_headers
        lib/kem_encrypt_impl.h
        lib/kem_decrypt_impl.h
        lib/kem_generate_keypair_impl.h
        lib/hash_sha3_impl.h
    )
endif()

########################################################################
# Create library
########################################################################
add_library(gnuradio-linux-crypto SHARED ${gr_linux_crypto_sources})

# Prefer /usr/local headers (e.g. libsodium 1.0.22) before system /usr/include
if(EXISTS "/usr/local/include")
    target_include_directories(gnuradio-linux-crypto BEFORE PRIVATE /usr/local/include)
endif()

# Ensure GNU Radio libraries are linked
# gr_register_component should set GNURADIO_LIBRARIES, but if not, use pkg-config
if(NOT GNURADIO_LIBRARIES)
    pkg_check_modules(GNURADIO_PMT gnuradio-pmt)
    set(GNURADIO_LIBRARIES ${GNURADIO_RUNTIME_LIBRARIES})
    if(GNURADIO_PMT_FOUND)
        list(APPEND GNURADIO_LIBRARIES ${GNURADIO_PMT_LIBRARIES})
    endif()
endif()

# If still empty, use direct library names
if(NOT GNURADIO_LIBRARIES)
    set(GNURADIO_LIBRARIES gnuradio-runtime)
    pkg_check_modules(GNURADIO_PMT QUIET gnuradio-pmt)
    if(GNURADIO_PMT_FOUND)
        list(APPEND GNURADIO_LIBRARIES gnuradio-pmt)
    endif()
endif()

target_link_libraries(gnuradio-linux-crypto
    ${GNURADIO_LIBRARIES}
    ${KEYUTILS_LIBRARIES}
)

# Add optional dependencies
if(OpenSSL_FOUND)
    target_link_libraries(gnuradio-linux-crypto OpenSSL::Crypto)
    target_compile_definitions(gnuradio-linux-crypto PRIVATE HAVE_OPENSSL)
endif()
if(GR_LINUX_CRYPTO_FIPS)
    target_compile_definitions(gnuradio-linux-crypto PRIVATE GR_LINUX_CRYPTO_FIPS)
endif()
if(GR_LINUX_CRYPTO_STRICT_BSI)
    target_compile_definitions(gnuradio-linux-crypto PRIVATE GR_LINUX_CRYPTO_STRICT_BSI)
endif()

if(SODIUM_FOUND AND TARGET sodium::sodium)
    target_link_libraries(gnuradio-linux-crypto sodium::sodium)
    target_compile_definitions(gnuradio-linux-crypto PRIVATE HAVE_SODIUM)
endif()

if(GPGME_FOUND)
    target_link_libraries(gnuradio-linux-crypto ${GPGME_LIBRARIES})
    target_include_directories(gnuradio-linux-crypto PRIVATE ${GPGME_INCLUDE_DIRS})
    target_compile_definitions(gnuradio-linux-crypto PRIVATE HAVE_GPGME)
endif()

if(NITROKEY_FOUND)
    target_link_libraries(gnuradio-linux-crypto ${NITROKEY_LIBRARIES})
    target_include_directories(gnuradio-linux-crypto PRIVATE ${NITROKEY_INCLUDE_DIRS})
    target_compile_definitions(gnuradio-linux-crypto PRIVATE HAVE_NITROKEY)
endif()

# Set library properties
set_target_properties(gnuradio-linux-crypto PROPERTIES
    VERSION ${GNURADIO_VERSION}
    SOVERSION ${GNURADIO_SOVERSION}
)

########################################################################
# Python bindings
########################################################################
if(ENABLE_PYTHON)
    find_package(Python3 COMPONENTS Interpreter Development)
    find_package(pybind11 REQUIRED)
    
    # Use Python's actual site-packages path so the module is on sys.path
    # (e.g. lib/python3.12/site-packages or lib/python3.12/dist-packages)
    if(Python3_SITELIB)
        set(LINUX_CRYPTO_PYTHON_INSTALL_DIR "${Python3_SITELIB}")
    else()
        set(LINUX_CRYPTO_PYTHON_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib/python${Python3_VERSION_MAJOR}.${Python3_VERSION_MINOR}/dist-packages")
    endif()
    message(STATUS "  Python bindings install dir: ${LINUX_CRYPTO_PYTHON_INSTALL_DIR}")
    
    # Create Python bindings (C++ sources only; .py files are not compiled by pybind11)
    pybind11_add_module(linux_crypto_python
        python/linux_crypto_python.cc
    )

    if(EXISTS "/usr/local/include")
        target_include_directories(linux_crypto_python BEFORE PRIVATE /usr/local/include)
    endif()
    
    target_link_libraries(linux_crypto_python PRIVATE
        gnuradio-linux-crypto
        gnuradio-runtime
        gnuradio-pmt
    )
    
    # Add OpenSSL support to Python bindings if available
    if(OpenSSL_FOUND)
        target_link_libraries(linux_crypto_python PRIVATE OpenSSL::Crypto)
        target_compile_definitions(linux_crypto_python PRIVATE HAVE_OPENSSL)
    endif()

    if(SODIUM_FOUND AND TARGET sodium::sodium)
        target_link_libraries(linux_crypto_python PRIVATE sodium::sodium)
        target_compile_definitions(linux_crypto_python PRIVATE HAVE_SODIUM)
    endif()
    
    # Set RPATH so Python module can find the library
    set_target_properties(linux_crypto_python PROPERTIES
        INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
    
    # Install Python module into Python's site path so it is importable
    install(TARGETS linux_crypto_python
        DESTINATION ${LINUX_CRYPTO_PYTHON_INSTALL_DIR}
    )
    
    # Install Python wrapper module to gnuradio package
    install(FILES python/gnuradio_linux_crypto_init.py
        DESTINATION ${LINUX_CRYPTO_PYTHON_INSTALL_DIR}/gnuradio
        RENAME linux_crypto.py
    )
    
    # Install gr_linux_crypto Python package (KeyringHelper, CryptoHelpers, etc.)
    install(FILES
        python/__init__.py
        python/keyring_helper.py
        python/crypto_helpers.py
        python/callsign_key_store.py
        python/callsign_verifier.py
        python/zmq_key_store_server.py
        python/zmq_key_store_client.py
        python/multi_recipient_ecies.py
        python/m17_frame.py
        python/linux_crypto_integration.py
        python/linux_crypto.py
        python/gdss_set_key_source.py
        python/galdralag_session_kdf.py
        python/ephemeral_key_store.py
        python/ephemeral_key_import_block.py
        python/hpke_brainpool.py
        python/shamir_secret_sharing.py
        python/nitrokey_bridge.py
        python/fips_status.py
        python/bsi_algorithm_boundary.py
        DESTINATION ${LINUX_CRYPTO_PYTHON_INSTALL_DIR}/gr_linux_crypto
    )
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/scripts/epk_generate.py"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/share/gr-linux-crypto/scripts"
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/scripts/gpg_qr_gen.py"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/share/gr-linux-crypto/scripts"
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/python/zmq_key_store_server.py"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/share/gr-linux-crypto/scripts"
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/scripts/zmq_key_store.service"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/share/gr-linux-crypto/scripts"
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )
endif()

########################################################################
# GRC blocks (explicit install so blocks and tree are always installed)
########################################################################
if(ENABLE_GRC)
    set(GRC_BLOCKS_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/share/gnuradio/grc/blocks")
    message(STATUS "  GRC blocks install dir: ${GRC_BLOCKS_INSTALL_DIR}")
    set(_gr_linux_crypto_grc_blocks
        grc/gr-linux-crypto.tree.yml
        grc/linux_crypto_gdss_set_key_source.block.yml
        grc/linux_crypto_ephemeral_key_import.block.yml
        grc/linux_crypto_kernel_keyring_source.block.yml
        grc/linux_crypto_kernel_crypto_aes.block.yml
        grc/linux_crypto_nitrokey_interface.block.yml
        grc/kernel_keyring_source.block.yml
        grc/kernel_aes_encrypt.block.yml
        grc/nitrokey_sign.block.yml
        grc/brainpool_ecies_encrypt.block.yml
        grc/brainpool_ecies_decrypt.block.yml
        grc/brainpool_ecies_multi_encrypt.block.yml
        grc/brainpool_ecies_multi_decrypt.block.yml
    )
    if(SODIUM_FOUND)
        list(APPEND _gr_linux_crypto_grc_blocks
            grc/linux_crypto_kem_generate_keypair.block.yml
            grc/linux_crypto_kem_encrypt.block.yml
            grc/linux_crypto_kem_decrypt.block.yml
            grc/linux_crypto_hash_sha3.block.yml
        )
    endif()
    install(FILES ${_gr_linux_crypto_grc_blocks}
        DESTINATION ${GRC_BLOCKS_INSTALL_DIR}
    )
endif()

########################################################################
# Examples
########################################################################
if(ENABLE_EXAMPLES)
    install(DIRECTORY examples/
        DESTINATION ${CMAKE_INSTALL_PREFIX}/share/gr-linux-crypto/examples
        FILES_MATCHING PATTERN "*.py"
    )
endif()

########################################################################
# Documentation
########################################################################
if(ENABLE_DOXYGEN)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        install(DIRECTORY docs/
            DESTINATION ${CMAKE_INSTALL_PREFIX}/share/gr-linux-crypto/docs
        )
    endif()
endif()

########################################################################
# Installation
########################################################################
install(TARGETS gnuradio-linux-crypto
    EXPORT gnuradio-linux-crypto-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
)

install(DIRECTORY include/gnuradio/linux_crypto/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include/gnuradio/linux_crypto
    FILES_MATCHING PATTERN "*.h"
)

########################################################################
# Testing
########################################################################
if(ENABLE_TESTING)
    enable_testing()
    
    # Test targets will be added when test files are created
    message(STATUS "  Testing enabled but no test files found")
endif()

########################################################################
# Fuzzing (optional)
########################################################################
if(ENABLE_FUZZING)
    find_program(AFL_PLUS_PLUS afl-fuzz)
    if(AFL_PLUS_PLUS)
        # Add fuzzing targets
        add_executable(fuzz_kernel_keyring
            security/fuzzing/kernel_keyring_fuzz_adapted.cpp
        )
        target_link_libraries(fuzz_kernel_keyring
            gnuradio-linux-crypto
            ${GNURADIO_LIBRARIES}
        )
        
        # Install fuzzing scripts
        install(DIRECTORY security/fuzzing/
            DESTINATION ${CMAKE_INSTALL_PREFIX}/share/gr-linux-crypto/fuzzing
            FILES_MATCHING PATTERN "*.cpp" PATTERN "*.sh"
        )
    endif()
endif()

########################################################################
# Uninstall target
########################################################################
# Configure uninstall script
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY
)

# Add uninstall target
add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
    COMMENT "Uninstalling gr-linux-crypto"
)

########################################################################
# SBOM generation (optional)
########################################################################
if(GR_LINUX_CRYPTO_SBOM)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_FOUND)
        set(SBOM_SCRIPT "${CMAKE_SOURCE_DIR}/scripts/generate_sbom.py")
        set(SBOM_ARGS
            --build-dir "${CMAKE_BINARY_DIR}"
            --source-dir "${CMAKE_SOURCE_DIR}"
            --version "1.0.0"
        )
        if(GR_LINUX_CRYPTO_FIPS)
            list(APPEND SBOM_ARGS --fips)
        endif()
        if(GR_LINUX_CRYPTO_PQ_KEM)
            list(APPEND SBOM_ARGS --pq-kem)
        endif()
        if(NITROKEY_FOUND)
            list(APPEND SBOM_ARGS --nitrokey)
        endif()
        add_custom_target(sbom ALL
            COMMAND ${Python3_EXECUTABLE} ${SBOM_SCRIPT} ${SBOM_ARGS}
            COMMENT "Generating SBOM (CycloneDX + SPDX)"
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        )
        message(STATUS "  SBOM generation: ON (build/sbom.cdx.json, build/sbom.spdx.json)")
    else()
        message(WARNING "GR_LINUX_CRYPTO_SBOM=ON but Python3 not found; SBOM generation disabled")
    endif()
endif()

########################################################################
# Configuration summary
########################################################################
message(STATUS "gr-linux-crypto configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
if(DEFINED GNURADIO_RUNTIME_VERSION)
    message(STATUS "  GNU Radio version: ${GNURADIO_RUNTIME_VERSION} (minimum: ${GNURADIO_MIN_VERSION})")
else()
    message(STATUS "  GNU Radio version: ${GNURADIO_VERSION} (version check unavailable)")
endif()
if(OpenSSL_FOUND)
    message(STATUS "  OpenSSL support: ON (${OPENSSL_VERSION}, target OpenSSL::Crypto)")
else()
    message(STATUS "  OpenSSL support: OFF")
endif()
if(SODIUM_FOUND)
    message(STATUS "  Sodium support: ON (libsodium ${LIBSODIUM_VERSION_REPORT})")
else()
    message(STATUS "  Sodium support: OFF")
endif()
message(STATUS "  GPGME support: ${GPGME_FOUND}")
if(NITROKEY_FOUND)
    message(STATUS "  Nitrokey support: ON")
else()
    message(STATUS "  Nitrokey support: OFF (optional, libnitrokey not installed)")
endif()
message(STATUS "  Python bindings: ${ENABLE_PYTHON}")
message(STATUS "  GRC blocks: ${ENABLE_GRC}")
message(STATUS "  Examples: ${ENABLE_EXAMPLES}")
message(STATUS "  FIPS mode: ${GR_LINUX_CRYPTO_FIPS}")
message(STATUS "  PQ KEM: ${GR_LINUX_CRYPTO_PQ_KEM}")
message(STATUS "  SBOM: ${GR_LINUX_CRYPTO_SBOM}")
message(STATUS "  Strict BSI (algorithm boundary): ${GR_LINUX_CRYPTO_STRICT_BSI}")
message(STATUS "  Documentation: ${ENABLE_DOXYGEN}")
message(STATUS "  Testing: ${ENABLE_TESTING}")
message(STATUS "  Fuzzing: ${ENABLE_FUZZING}")
message(STATUS "")
message(STATUS "  Forward compatibility: Designed for future GNU Radio versions")
message(STATUS "  See COMPATIBILITY.md for version compatibility details")

endif(ENABLE_GR_LINUX_CRYPTO)
