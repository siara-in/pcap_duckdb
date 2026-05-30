cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME pcap_duckdb)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(src/include)

set(EXTENSION_SOURCES src/pcap_duckdb_extension.cpp)

# Find libpcap - prefer vcpkg's version via pkg-config or cmake config
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PCAP libpcap)
endif()

if(NOT PCAP_FOUND)
  find_path(PCAP_INCLUDE_DIR pcap/pcap.h REQUIRED)
  find_library(PCAP_LIBRARY pcap REQUIRED)
  set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
  set(PCAP_LIBRARIES ${PCAP_LIBRARY})
endif()

# Add pcap includes globally so generated_extension_loader.cpp can find pcap_duckdb_extension.hpp
include_directories(${PCAP_INCLUDE_DIRS})

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

target_include_directories(${EXTENSION_NAME} PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(${EXTENSION_NAME} ${PCAP_LIBRARIES})

target_include_directories(${LOADABLE_EXTENSION_NAME} PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(${LOADABLE_EXTENSION_NAME} ${PCAP_LIBRARIES})

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
