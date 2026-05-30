cmake_minimum_required(VERSION 3.10)

set(TARGET_NAME pcap_duckdb)
set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(src/include)

set(EXTENSION_SOURCES src/pcap_duckdb_extension.cpp)

# Find libpcap - try pkg-config first (works on Linux/vcpkg),
# fall back to find_path/find_library (works on macOS, Windows)
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PCAP libpcap)
endif()

if(PCAP_FOUND)
  include_directories(${PCAP_INCLUDE_DIRS})
  # Construct full path to static lib instead of relying on PCAP_STATIC_LIBRARIES
  find_library(PCAP_STATIC_LIB
    NAMES libpcap.a pcap
    HINTS ${PCAP_LIBRARY_DIRS}
    NO_DEFAULT_PATH
  )
  if(NOT PCAP_STATIC_LIB)
    message(FATAL_ERROR "Could not find libpcap.a in ${PCAP_LIBRARY_DIRS}")
  endif()
  message(STATUS "PCAP_STATIC_LIB resolved to: ${PCAP_STATIC_LIB}")
  set(PCAP_LINK_LIBS ${PCAP_STATIC_LIB})
  set(PCAP_LINK_DIRS ${PCAP_LIBRARY_DIRS})
else()
  find_path(PCAP_INCLUDE_DIR pcap/pcap.h REQUIRED)
  find_library(PCAP_LIBRARY pcap REQUIRED)
  include_directories(${PCAP_INCLUDE_DIR})
  set(PCAP_LINK_LIBS ${PCAP_LIBRARY})
  set(PCAP_LINK_DIRS "")
endif()

message(STATUS "PCAP_FOUND: ${PCAP_FOUND}")
message(STATUS "PCAP_INCLUDE_DIRS: ${PCAP_INCLUDE_DIRS}")
message(STATUS "PCAP_LIBRARIES: ${PCAP_LIBRARIES}")
message(STATUS "PCAP_STATIC_LIBRARIES: ${PCAP_STATIC_LIBRARIES}")
message(STATUS "PCAP_LIBRARY_DIRS: ${PCAP_LIBRARY_DIRS}")

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

target_include_directories(${EXTENSION_NAME} PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(${EXTENSION_NAME} ${PCAP_LINK_LIBS})
target_link_directories(${EXTENSION_NAME} PRIVATE ${PCAP_LINK_DIRS})

target_include_directories(${LOADABLE_EXTENSION_NAME} PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(${LOADABLE_EXTENSION_NAME} ${PCAP_LINK_LIBS})
target_link_directories(${LOADABLE_EXTENSION_NAME} PRIVATE ${PCAP_LINK_DIRS})

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
