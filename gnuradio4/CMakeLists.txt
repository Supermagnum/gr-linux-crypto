# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

# GNU Radio 4 upstream headers include <print>; require a toolchain that ships it (e.g. GCC 14+).
if(NOT CMAKE_CXX_COMPILER)
  foreach(_gxx IN ITEMS g++-16 g++-15 g++-14)
    find_program(_gr_linux_crypto4cxx NAMES "${_gxx}")
    if(_gr_linux_crypto4cxx)
      set(CMAKE_CXX_COMPILER "${_gr_linux_crypto4cxx}" CACHE STRING "CXX compiler detected for GR4 (<print>)" FORCE)
      break()
    endif()
  endforeach()
endif()

project(
  gr-linux-crypto4
  VERSION 0.1.0
  LANGUAGES CXX
  DESCRIPTION "GNU Radio 4.0 Linux cryptography OOT (Brainpool, AF_ALG, keyutils, optional Nitrokey)")

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "gr-linux-crypto4 is Linux-only (AF_ALG, kernel keyring).")
endif()

option(GR_LINUX_CRYPTO4_BUILD_TESTS "Build Boost.UT tests" ON)

find_package(gnuradio4 REQUIRED CONFIG)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(PkgConfig QUIET)
find_package(Threads REQUIRED)

find_library(KEYUTILS_LIBRARY NAMES keyutils REQUIRED)

set(GR_LINUX_CRYPTO4_HAVE_NITROKEY OFF)
if(PkgConfig_FOUND)
  pkg_check_modules(LIBNITROKEY IMPORTED_TARGET libnitrokey)
  if(TARGET PkgConfig::LIBNITROKEY)
    set(GR_LINUX_CRYPTO4_HAVE_NITROKEY ON)
  endif()
endif()

set(GR_LINUX_CRYPTO4_SOURCES
    src/brainpool_ec_impl.cpp
    src/ecies_codec.cpp
    src/callsign_store.cpp
    src/multi_recipient_ecies.cpp
    src/afalg_aes.cpp
    src/kernel_keyring_detail.cpp)

add_library(gr-linux-crypto STATIC ${GR_LINUX_CRYPTO4_SOURCES})
add_library(gnuradio4::gr-linux-crypto ALIAS gr-linux-crypto)

target_include_directories(
  gr-linux-crypto
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include>)

target_link_libraries(
  gr-linux-crypto
  PUBLIC gnuradio4::gnuradio-core
         gnuradio4::gnuradio-blocklib-core
         OpenSSL::Crypto
         Threads::Threads)

target_link_libraries(gr-linux-crypto PUBLIC ${KEYUTILS_LIBRARY})

if(GR_LINUX_CRYPTO4_HAVE_NITROKEY)
  target_link_libraries(gr-linux-crypto PUBLIC PkgConfig::LIBNITROKEY)
  target_compile_definitions(gr-linux-crypto PUBLIC HAVE_NITROKEY=1)
endif()

install(TARGETS gr-linux-crypto EXPORT gr-linux-crypto4-targets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
                                                         INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(
  EXPORT gr-linux-crypto4-targets
  FILE gr-linux-crypto4-targets.cmake
  NAMESPACE gnuradio4::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/gr-linux-crypto4)

include(CMakePackageConfigHelpers)
configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/gr-linux-crypto4-config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/gr-linux-crypto4-config.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/gr-linux-crypto4)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/gr-linux-crypto4-config-version.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/gr-linux-crypto4-config.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/gr-linux-crypto4-config-version.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/gr-linux-crypto4)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/gnuradio4-gr-linux-crypto.pc.in"
               "${CMAKE_CURRENT_BINARY_DIR}/gnuradio4-gr-linux-crypto.pc" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/gnuradio4-gr-linux-crypto.pc"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(GR_LINUX_CRYPTO4_BUILD_TESTS)
  include(FetchContent)
  set(BOOST_UT_DISABLE_MODULE ON CACHE BOOL "Disable UT Module Support" FORCE)
  FetchContent_Declare(
    ut
    GIT_REPOSITORY https://github.com/boost-ext/ut.git
    GIT_TAG 53e17f25119598c6458d30351b260193096ba67e
    EXCLUDE_FROM_ALL)
  FetchContent_MakeAvailable(ut)
  enable_testing()
  add_subdirectory(test)
endif()
