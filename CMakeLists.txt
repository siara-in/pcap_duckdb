cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME pcap_duckdb)

# DuckDB's extension distribution supports vcpkg. As such, dependencies can be added in ./vcpkg.json and then
# used in cmake with find_package. Feel free to remove or replace with other dependencies.
# Note that it should also be removed from vcpkg.json to prevent needlessly installing it..
find_package(OpenSSL REQUIRED)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(src/include)

set(EXTENSION_SOURCES src/pcap_duckdb_extension.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# 1. Find the header
find_path(PCAP_INCLUDE_DIR pcap.h)

# 2. Find the library file
find_library(PCAP_LIBRARY pcap)

if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    message(STATUS "Found libpcap: ${PCAP_LIBRARY}")

    # Static extension
    target_include_directories(${TARGET_NAME}_extension PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(${TARGET_NAME}_extension ${PCAP_LIBRARY})

    # Loadable (dynamic) extension  ← THIS WAS MISSING
    target_include_directories(${TARGET_NAME}_loadable_extension PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(${TARGET_NAME}_loadable_extension ${PCAP_LIBRARY})

else()
    message(FATAL_ERROR "Could not find libpcap. Try: brew install libpcap")
endif()

# Link Android log library only when building for Android
# if(ANDROID)
#     target_link_libraries(${TARGET_NAME}_extension 
#         log  # This links liblog.so for __android_log_print
#     )
# endif()

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
