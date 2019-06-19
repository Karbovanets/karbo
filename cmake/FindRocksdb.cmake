
# Copyright (c) 2016-2019, The Karbo developers
#
# This file is part of Karbo.
#
# Karbo is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Karbo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Karbo.  If not, see <http://www.gnu.org/licenses/>.


if (UNIX)
  set(ROCKSDB_LIB_NAME_STATIC "librocksdb.a")
  set(ROCKSDB_LIB_NAME_SHARED "librocksdb.so")
else()
  set(ROCKSDB_LIB_NAME_STATIC "rocksdb.lib")
  set(ROCKSDB_LIB_NAME_SHARED "rocksdb.dll")
endif()

if (ROCKSDB_INCLUDE_DIRS AND ROCKSDB_LIBRARY_DIRS)
  find_library(ROCKSDB_LIBRARIES ${ROCKSDB_LIB_NAME_STATIC} ${ROCKSDB_LIBRARY_DIRS} NO_DEFAULT_PATH)
  find_path(ROCKSDB_INCLUDE_DIR "rocksdb" ${ROCKSDB_INCLUDE_DIRS} NO_DEFAULT_PATH)
else()
  find_library(ROCKSDB_LIBRARIES ${ROCKSDB_LIB_NAME_STATIC})
  find_path(ROCKSDB_INCLUDE_DIR "rocksdb")
endif()

if (ROCKSDB_INCLUDE_DIR AND ROCKSDB_LIBRARIES)
  set(ROCKSDB_FOUND TRUE)
  file(STRINGS "${ROCKSDB_INCLUDE_DIR}/rocksdb/version.h" _ROCKSDB_VERSION_MAJOR_CONTENTS REGEX "#define ROCKSDB_MAJOR ")
  file(STRINGS "${ROCKSDB_INCLUDE_DIR}/rocksdb/version.h" _ROCKSDB_VERSION_MINOR_CONTENTS REGEX "#define ROCKSDB_MINOR ")
  file(STRINGS "${ROCKSDB_INCLUDE_DIR}/rocksdb/version.h" _ROCKSDB_VERSION_PATCH_CONTENTS REGEX "#define ROCKSDB_PATCH ")
  if("${_ROCKSDB_VERSION_MAJOR_CONTENTS}" MATCHES "#define ROCKSDB_MAJOR ([0-9]+)")
    set(_ROCKSDB_VERSION_MAJOR ${CMAKE_MATCH_1})
  endif()
  if("${_ROCKSDB_VERSION_MINOR_CONTENTS}" MATCHES "#define ROCKSDB_MINOR ([0-9]+)")
    set(_ROCKSDB_VERSION_MINOR ${CMAKE_MATCH_1})
  endif()
  if("${_ROCKSDB_VERSION_PATCH_CONTENTS}" MATCHES "#define ROCKSDB_PATCH ([0-9]+)")
    set(_ROCKSDB_VERSION_PATCH ${CMAKE_MATCH_1})
  endif()
  if (_ROCKSDB_VERSION_MAJOR AND _ROCKSDB_VERSION_MINOR AND _ROCKSDB_VERSION_PATCH)
    set(ROCKSDB_VERSION_MAJOR ${_ROCKSDB_VERSION_MAJOR})
    set(ROCKSDB_VERSION_MINOR ${_ROCKSDB_VERSION_MINOR})
    set(ROCKSDB_VERSION_PATCH ${_ROCKSDB_VERSION_PATCH})
    set(ROCKSDB_VERSION "${_ROCKSDB_VERSION_MAJOR}.${_ROCKSDB_VERSION_MINOR}.${_ROCKSDB_VERSION_PATCH}")
  endif()
  message(STATUS "RocksDB version: ${ROCKSDB_VERSION}")
else()
  message(STATUS "Can`t find RocksDB installed")
  set(ROCKSDB_FOUND FALSE)
endif()

