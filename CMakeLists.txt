cmake_minimum_required(VERSION 3.10...4.10)

project(qadmimes VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_library(qadmimes-core STATIC
            src/core/src/qadmimes.cpp
            src/core/src/magic_database.cpp)

target_include_directories(qadmimes-core PUBLIC src/core/include)

add_executable(qadmimes src/cli/main.cpp)
target_link_libraries(qadmimes PRIVATE qadmimes-core)

include(GNUInstallDirs)
install(TARGETS qadmimes DESTINATION ${CMAKE_INSTALL_BINDIR})
