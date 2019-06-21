set(UPNPC_BUILD_STATIC ON CACHE BOOL "Build static library")
set(UPNPC_BUILD_SHARED OFF CACHE BOOL "Build shared library")
set(UPNPC_BUILD_TESTS OFF CACHE BOOL "Build test executables")
set(WITH_MD_LIBRARY OFF CACHE BOOL "Code Generation for static library")

add_subdirectory(miniupnpc)

if (NOT ROCKSDB_FOUND)
  if(MSVC)
    add_subdirectory(rocksDB EXCLUDE_FROM_ALL)
    set_property(TARGET upnpc-static rocksdb PROPERTY FOLDER "external")
  elseif(NOT MSVC)
    set_property(TARGET upnpc-static PROPERTY FOLDER "external")
    add_custom_target(
       rocksdb
       COMMAND $(MAKE) rocksdb
       WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/rocksdb
    )
    add_library(rocksdblib STATIC IMPORTED GLOBAL)
    set_target_properties(rocksdblib PROPERTIES IMPORTED_LOCATION ${PROJECT_BINARY_DIR}/rocksdb/librocksdb.a)
    add_dependencies(rocksdblib rocksdb)
  endif()
endif()

if(MSVC)
  set_property(TARGET upnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -wd4244 -wd4267")
elseif(FREEBSD)
  set_property(TARGET upnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -D_XOPEN_SOURCE=600 -Wno-undef -Wno-unused-result -Wno-unused-value")
else()
  set_property(TARGET upnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-undef -Wno-unused-result -Wno-unused-value")
endif()

