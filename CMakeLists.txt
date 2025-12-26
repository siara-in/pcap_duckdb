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

if(WIN32)
    find_package(Pcap CONFIG REQUIRED)
    set(PCAP_LIBS Pcap::Pcap)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)
    set(PCAP_LIBS ${PCAP_LIBRARIES})
endif()

foreach(tgt
    ${TARGET_NAME}_extension
    ${TARGET_NAME}_loadable_extension
)
    target_include_directories(${tgt} PRIVATE ${PCAP_INCLUDE_DIRS})
    target_link_libraries(${tgt} PRIVATE ${PCAP_LIBS})
endforeach()

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
