cmake_minimum_required(VERSION 3.5)
project(Karbo)

# Required for finding Threads on ARM
enable_language(C)
enable_language(CXX)

find_package(Threads)

set(VERSION "0.1")

## This section describes our general CMake setup options
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_CONFIGURATION_TYPES "Debug; RelWithDebInfo; Release" CACHE STRING INTERNAL)
set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build, options are: Debug, Release, RelWithDebInfo")
set(CMAKE_SKIP_INSTALL_RULES OFF FORCE)
set(CMAKE_SKIP_PACKAGE_ALL_DEPENDENCY ON FORCE)
set(CMAKE_SUPPRESS_REGENERATION ON)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

## This section is specifically for RocksDB build options that we've disabled for maximum portability
set(ENABLE_AVX OFF CACHE STRING "Enable RocksDB AVX/AVX2? Defaults to OFF")
set(ENABLE_LEAF_FRAME OFF CACHE STRING "Enable RocksDB OMIT_LEAF_FRAME_POINTER detection? Defaults to OFF")
set(ENABLE_SSE42 OFF CACHE STRING "Enable RocksDB SSE4.2 support detection? Defaults to OFF")
set(ENABLE_THREAD_LOCAL OFF CACHE STRING "Enable RocksDB THREAD_LOCAL support detection? Defaults to OFF")
set(ENABLE_SYNC_FILE_RANGE_WRITE OFF CACHE STRING "Enable RocksDB SYNC_FILE_RANGE_WRITE support detection? Defaults to OFF")
set(ENABLE_PTHREAD_MUTEX_ADAPTIVE_NP OFF CACHE STRING "Enable RocksDB PTHREAD_MUTEX_ADAPTIVE_NP support detection? Defaults to OFF")
set(ENABLE_MALLOC_USABLE_SIZE OFF CACHE STRING "Enable RocksDB MALLOC_USABLE_SIZE support detection? Defaults to OFF")
set(ENABLE_SCHED_GETCPU OFF CACHE STRING "Enable RocksDB SCHED_GETCPU support detection? Defaults to OFF")
set(WITH_ZSTD ON CACHE BOOL "Enable zstd compression")

option(WITH_LITE_WALLET "Lite wallet specific" OFF)

if (NOT ARCH OR ARCH STREQUAL "" OR ARCH STREQUAL "native" OR ARCH STREQUAL "default")
  set(ARCH_ID "${CMAKE_SYSTEM_PROCESSOR}")
else()
  set(ARCH_ID "${ARCH}")
endif()
string(TOLOWER "${ARCH_ID}" ARM_ID)
if (ARM_ID)
  string(SUBSTRING "${ARM_ID}" 0 3 ARM_TEST)
endif()
if (ARM_TEST STREQUAL "arm")
  set(ARM 1)
  string(SUBSTRING "${ARM_ID}" 0 5 ARM_TEST)
  if (ARM_TEST STREQUAL "armv6")
    set(ARM6 1)
  endif()
  if (ARM_TEST STREQUAL "armv7")
    set(ARM7 1)
  endif()
endif()

if (ARM_ID STREQUAL "aarch64" OR ARM_ID STREQUAL "arm64" OR ARM_ID STREQUAL "armv8-a")
  set(ARM 1)
  set(ARM8 1)
  set(ARCH "armv8-a")
endif()

if(ARCH_ID STREQUAL "ppc64le")
  set(PPC64LE 1)
endif()

# Check if we're on BSD
if (CMAKE_SYSTEM_NAME MATCHES "kFreeBSD.*|FreeBSD")
  set(FREEBSD TRUE)
endif()

if (CMAKE_SYSTEM_NAME MATCHES "DragonFly.*")
  set(DRAGONFLY TRUE)
endif()

if (CMAKE_SYSTEM_NAME MATCHES "kOpenBSD.*|OpenBSD.*")
  set(OPENBSD TRUE)
endif()

if(WITH_LITE_WALLET)
  add_definitions("-DUSE_LITE_WALLET")
endif()

if (WITH_ZSTD)
    add_definitions(-DENABLE_ZSTD_COMPRESSION)
endif ()

if(MSVC OR MINGW)
  set(DEFAULT_STATIC TRUE)
else()
  set(DEFAULT_STATIC FALSE)
endif()

set(STATIC ON CACHE BOOL FORCE "Link libraries statically? Forced to ON")

# This section helps us set up RocksDB for maximum portability
set(ENABLE_AVX OFF CACHE STRING "Enable RocksDB AVX/AVX2 support detection? Defaults to OFF")

## This section helps us tag our builds with the git commit information
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/version")
include("${CMAKE_SOURCE_DIR}/src/version.cmake")
set(VERSION "${VERSION}")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in" "${CMAKE_CURRENT_BINARY_DIR}/version/version.h")
add_custom_target(version ALL)

include_directories(include src external "${CMAKE_CURRENT_BINARY_DIR}/version")  

## Platform specific code base information is applied here
if(MSVC)
  include_directories(${CMAKE_SOURCE_DIR}/src/Platform/Windows)
  set (CMAKE_MSVC_FLAGS_BASE "/D_CRT_SECURE_NO_WARNINGS /wd4996 /wd4345 /D_WIN32_WINNT=0x0600 /DWIN32_LEAN_AND_MEAN /DGTEST_HAS_TR1_TUPLE=0 /D_VARIADIC_MAX=8 /D__SSE4_1__")
  set (CMAKE_MSVC_FLAGS_EXT "/bigobj /MP /W3 /GS-")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_MSVC_FLAGS_BASE} ${CMAKE_MSVC_FLAGS_EXT}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_MSVC_FLAGS_BASE} ${CMAKE_MSVC_FLAGS_EXT}")
  set(CMAKE_RC_FLAGS ${CMAKE_MSVC_FLAGS_BASE})
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:10485760")
  foreach(VAR CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_RELWITHDEBINFO CMAKE_C_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELEASE)
    string(REPLACE "/MD" "/MT" ${VAR} "${${VAR}}")
  endforeach()
  include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/src/platform/msc)
elseif(APPLE)
  include_directories(SYSTEM /usr/include/malloc)
  enable_language(ASM)
  include_directories(${CMAKE_SOURCE_DIR}/src/Platform/OSX)
  include_directories(${CMAKE_SOURCE_DIR}/src/Platform/Posix)
elseif(FREEBSD)
  enable_language(ASM)
  include_directories(${CMAKE_SOURCE_DIR}/src/Platform/FreeBSD)
  include_directories(${CMAKE_SOURCE_DIR}/src/Platform/Posix)
elseif(ANDROID)
  include_directories(${CMAKE_SOURCE_DIR}/src/Platform/Android)
  include_directories(${CMAKE_SOURCE_DIR}/src/Platform/Posix)
else()
  include_directories(${CMAKE_SOURCE_DIR}/src/Platform/Linux)
  include_directories(${CMAKE_SOURCE_DIR}/src/Platform/Posix)
endif()

if(NOT MSVC)
  if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    # This option has no effect in glibc version less than 2.20.
    # Since glibc 2.20 _BSD_SOURCE is deprecated, this macro is recomended instead
    add_definitions("-D_DEFAULT_SOURCE -D_GNU_SOURCE")
  endif()

  ## This is here to support building for multiple architecture types... but we all know how well that usually goes...
  set(ARCH default CACHE STRING "CPU to build for: -march value or default")
  if("${ARCH}" STREQUAL "default")
    set(ARCH_FLAG "")
  else()
    set(ARCH_FLAG "-march=${ARCH}")
  endif()

  ## These options generate all those nice warnings we see while building
  set(WARNINGS "-Wall -Wextra -Wpointer-arith -Wundef -Wvla -Wwrite-strings  -Wno-error=extra -Wno-error=unused-function -Wno-error=deprecated-declarations -Wno-error=sign-compare -Wno-error=strict-aliasing -Wno-error=type-limits -Wno-unused-parameter -Wno-error=unused-variable -Wno-error=undef -Wno-error=uninitialized -Wno-error=unused-result")
  if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set(WARNINGS "${WARNINGS} -Wno-error=mismatched-tags -Wno-error=null-conversion -Wno-overloaded-shift-op-parentheses -Wno-error=shift-count-overflow -Wno-error=tautological-constant-out-of-range-compare -Wno-error=unused-private-field -Wno-error=unneeded-internal-declaration -Wno-error=unused-function -Wno-error=missing-braces")
  else()
    set(WARNINGS "${WARNINGS} -Wlogical-op -Wno-error=maybe-uninitialized -Wno-error=clobbered -Wno-error=unused-but-set-variable")
  endif()

  if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(WARNINGS "${WARNINGS} -Wno-error=odr")
  endif()
  set(C_WARNINGS "-Waggregate-return -Wnested-externs -Wold-style-definition -Wstrict-prototypes")
  set(CXX_WARNINGS "-Wno-reorder -Wno-missing-field-initializers")

  if(NOT ARM AND NOT PPC64LE)
    message(STATUS "AES support enabled")
    set(MAES_FLAG "-maes")
  elseif(PPC64LE)
    message(STATUS "AES support not available on ppc64le")
  elseif(ARM6)
    message(STATUS "AES support not available on ARMv6")
  elseif(ARM7)
    message(STATUS "AES support not available on ARMv7")
  elseif(ARM8)
    CHECK_CXX_ACCEPTS_FLAG("-march=${ARCH}+crypto" ARCH_PLUS_CRYPTO)
    if(ARCH_PLUS_CRYPTO)
      message(STATUS "Crypto extensions enabled for ARMv8")
      set(ARCH_FLAG "${ARCH_FLAG} -march=${ARCH}+crypto")
    else()
      message(STATUS "Crypto extensions unavailable on your ARMv8 device")
    endif()
  else()
    message(STATUS "AES support disabled")
  endif()

  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 ${STATICASSERTC_FLAG} ${WARNINGS} ${C_WARNINGS} ${ARCH_FLAG} ${MAES_FLAG}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 ${STATICASSERTCPP_FLAG} ${WARNINGS} ${CXX_WARNINGS} ${ARCH_FLAG} ${MAES_FLAG}")

  if (APPLE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DGTEST_HAS_TR1_TUPLE=0 -DBOOST_NO_AUTO_PTR")
  endif ()

  if(NOT APPLE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
  endif()

  ## Setting up DEBUG flags
  if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND NOT (CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8))
    set(DEBUG_FLAGS "-g3 -Og -gdwarf-4 -fvar-tracking -fvar-tracking-assignments -fno-inline -fno-omit-frame-pointer")
  else()
    set(DEBUG_FLAGS "-g3 -O0 -fno-omit-frame-pointer")
  endif()

  ## Setting up RELEASE flags
  set(RELEASE_FLAGS "-Ofast -DNDEBUG -Wno-unused-variable")

  if(NOT APPLE)
    # There is a clang bug that does not allow to compile code that uses AES-NI intrinsics if -flto is enabled
    if (CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_SYSTEM_NAME STREQUAL "Linux"
        AND CMAKE_BUILD_TYPE STREQUAL "Release" AND ((CMAKE_C_COMPILER_VERSION VERSION_GREATER 4.9) OR (CMAKE_C_COMPILER_VERSION VERSION_EQUAL 4.9)))
      # On linux, to build in lto mode, check that ld.gold linker is used: 'update-alternatives --install /usr/bin/ld ld /usr/bin/ld.gold HIGHEST_PRIORITY'
      set(CMAKE_AR gcc-ar)
      set(CMAKE_RANLIB gcc-ranlib)
    endif()
  endif()

  if(ANDROID AND NOT IOS)
    #From Android 5: "only position independent executables (PIE) are supported" 
    message(STATUS "Enabling PIE executable")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -DANDROID -DBOOST_COROUTINES_NO_DEPRECATION_WARNING")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -pie -ldl -pthread")	
  endif()
 
  if (ANDROID OR IOS)
    add_definitions(-DFORCE_USE_HEAP=1)
  endif()

  if(ANDROID)
    set(ATOMIC libboost_atomic.a)
    set(THREAD libboost_thread.a)
  endif()

  if(CMAKE_C_COMPILER_ID STREQUAL "Clang" AND ARCH_WIDTH EQUAL "32" AND NOT IOS)
    find_library(ATOMIC atomic)
    find_library(THREAD thread)
    list(APPEND EXTRA_LIBRARIES ${ATOMIC})
    list(APPEND EXTRA_LIBRARIES ${THREAD})
  endif()

  ## Set up the normal CMake flags as we've built them
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${DEBUG_FLAGS}")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${DEBUG_FLAGS}")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${RELEASE_FLAGS}")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${RELEASE_FLAGS}")

  ## Statically link our binaries
  if (STATIC AND NOT (APPLE OR FREEBSD OR OPENBSD OR DRAGONFLY))
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
  endif()
endif()

## Go get us some static BOOST libraries
set(Boost_NO_BOOST_CMAKE ON)
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_STATIC_RUNTIME ON)
find_package(Boost REQUIRED COMPONENTS system filesystem thread date_time chrono regex serialization program_options coroutine context atomic)
message(STATUS "Boost Found: ${Boost_INCLUDE_DIRS}")
include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
if(APPLE OR OPENBSD OR ANDROID)
  set(Boost_LIBRARIES "${Boost_LIBRARIES}")
elseif(NOT MSVC)
  set(Boost_LIBRARIES "${Boost_LIBRARIES};rt")
endif()

find_package(Rocksdb 5.15.10)
if (STATIC)
  set (OPENSSL_USE_STATIC_LIBS ON)
  add_definitions("-DUPNP_STATIC -DMINIUPNP_STATICLIB -DUPNPC_BUILD_STATIC")
endif ()
if (MSVC)
  set(OPENSSL_MSVC_STATIC_RT ON)
endif ()

# We have to look for Homebrew OpenSSL a bit differently
# Borrowed from https://github.com/tarantool/tarantool/commit/6eab201af1843f53a833c8928dc58fceffa08147
if (APPLE)
    find_program(HOMEBREW_EXECUTABLE brew)
    execute_process(COMMAND ${HOMEBREW_EXECUTABLE} --prefix openssl
            OUTPUT_VARIABLE HOMEBREW_OPENSSL
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    if (DEFINED HOMEBREW_OPENSSL)
        if (NOT DEFINED OPENSSL_ROOT_DIR)
            message(STATUS "Setting OpenSSL root to ${HOMEBREW_OPENSSL}")
            set(OPENSSL_ROOT_DIR "${HOMEBREW_OPENSSL}")
        endif ()
    endif ()
endif ()

find_package(OpenSSL)

if (NOT OPENSSL_FOUND)
    find_package(PkgConfig)

    if (PKG_CONFIG_FOUND)
        pkg_search_module(OPENSSL openssl)
    endif()
endif()

if (OPENSSL_FOUND)
    ## On non MSVC build systems, we need to link ldl with the static OpenSSL library
    if (NOT MSVC)
        set(OPENSSL_LIBRARIES "${OPENSSL_LIBRARIES};dl")
    endif ()

    include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
    message(STATUS "OpenSSL Found: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
else ()
    message(STATUS "OpenSSL Found: No... Skipping...")
endif ()

add_subdirectory(external)
add_subdirectory(src)

## We need to setup the RocksDB build environment to match our system
include_directories(${CMAKE_SOURCE_DIR}/external/zstd/lib)
if (NOT ROCKSDB_FOUND)
  if(NOT MSVC)
    execute_process(
      COMMAND ${CMAKE_COMMAND} ${CMAKE_SOURCE_DIR}/external/rocksdb -DARCH=${ARCH} -DWITH_ZSTD=${WITH_ZSTD} -DWITH_GFLAGS=0 -DCMAKE_BUILD_TYPE=MinSizeRel -DWITH_TESTS=OFF -DWITH_TOOLS=OFF -DPORTABLE=ON -B${PROJECT_BINARY_DIR}/rocksdb
    )
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${PROJECT_BINARY_DIR}/rocksdb/librocksdb.a")
  endif()
endif()
