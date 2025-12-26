cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME pcap_duckdb)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(src/include)

set(EXTENSION_SOURCES src/pcap_duckdb_extension.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

if(VCPKG_TOOLCHAIN)
    set(PCAP_ROOT "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")

    find_library(PCAP_LIBRARY
        NAMES pcap
        PATHS "${PCAP_ROOT}/lib"
        NO_DEFAULT_PATH
        REQUIRED
    )

    add_library(pcap_vcpkg UNKNOWN IMPORTED)
    set_target_properties(pcap_vcpkg PROPERTIES
        IMPORTED_LOCATION "${PCAP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${PCAP_ROOT}/include"
    )
endif()

target_link_libraries(${EXTENSION_NAME} PRIVATE pcap_vcpkg)
target_link_libraries(${LOADABLE_EXTENSION_NAME} PRIVATE pcap_vcpkg)
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
