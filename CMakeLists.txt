cmake_minimum_required(VERSION 3.20)

project(recsrmesh C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Find mbedtls
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(MbedTLS REQUIRED)
find_package(Threads REQUIRED)

# Library sources (no main, just library code)
file(GLOB_RECURSE SOURCES "src/*.cpp")
list(APPEND SOURCES src/uecc_p192.c)

add_library(recsrmesh STATIC ${SOURCES})

target_compile_features(recsrmesh PUBLIC cxx_std_20)

target_include_directories(recsrmesh PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MBEDTLS_INCLUDE_DIRS}
)
target_include_directories(recsrmesh PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/external/micro-ecc)

target_compile_options(recsrmesh PRIVATE -Wall -Wextra)

target_link_libraries(recsrmesh PUBLIC
    ${MBEDTLS_LIBRARIES}
    mbedcrypto
    Threads::Threads
)

# Linux-specific
if(UNIX AND NOT APPLE)
    target_link_libraries(recsrmesh PRIVATE pthread)
endif()

# Installation
install(TARGETS recsrmesh
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(DIRECTORY include/ DESTINATION include)

option(RECSRMESH_BUILD_TESTS "Build known-answer tests" ON)
if(RECSRMESH_BUILD_TESTS)
    enable_testing()
    add_executable(test_crypto tests/test_crypto.cpp)
    target_include_directories(test_crypto PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/external/micro-ecc)
    target_link_libraries(test_crypto PRIVATE recsrmesh)
    add_test(NAME test_crypto COMMAND test_crypto)
endif()
