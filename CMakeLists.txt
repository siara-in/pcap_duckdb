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
  # pkg-config path (Linux CI with vcpkg)
  include_directories(${PCAP_INCLUDE_DIRS})
  set(PCAP_LINK_LIBS ${PCAP_STATIC_LIBRARIES})
  set(PCAP_LINK_DIRS ${PCAP_LIBRARY_DIRS})
else()
  # Fallback: direct search (macOS with homebrew/system, Windows)
  find_path(PCAP_INCLUDE_DIR pcap/pcap.h REQUIRED)
  find_library(PCAP_LIBRARY pcap REQUIRED)
  include_directories(${PCAP_INCLUDE_DIR})
  set(PCAP_LINK_LIBS ${PCAP_LIBRARY})
  set(PCAP_LINK_DIRS "")
endif()

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
