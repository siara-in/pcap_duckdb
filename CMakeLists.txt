cmake_minimum_required(VERSION 3.5)

if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE
        "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING ""
    )
endif()

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

# First try vcpkg / config-mode
find_package(Pcap CONFIG QUIET)

if(Pcap_FOUND)
    message(STATUS "Using Pcap from find_package")

    target_link_libraries(${TARGET_NAME}_extension
        PRIVATE Pcap::Pcap
    )
    target_link_libraries(${TARGET_NAME}_loadable_extension
        PRIVATE Pcap::Pcap
    )

else()
    message(STATUS "Falling back to manual libpcap discovery")

    find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
    find_library(PCAP_LIBRARY pcap)

    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR "Could not find libpcap")
    endif()

    find_package(Threads REQUIRED)

    foreach(tgt
        ${TARGET_NAME}_extension
        ${TARGET_NAME}_loadable_extension
    )
        target_include_directories(${tgt} PRIVATE ${PCAP_INCLUDE_DIR})
        target_link_libraries(${tgt}
            PRIVATE
                ${PCAP_LIBRARY}
                Threads::Threads
        )
        if(UNIX AND NOT APPLE)
            target_link_libraries(${tgt} PRIVATE dl rt)
        endif()
    endforeach()
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
