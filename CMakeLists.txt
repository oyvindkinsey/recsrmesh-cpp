cmake_minimum_required(VERSION 3.20)

project(recsrmesh CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Find mbedtls
find_package(MbedTLS REQUIRED)

# Library sources (no main, just library code)
file(GLOB_RECURSE SOURCES "src/*.cpp")

add_library(recsrmesh STATIC ${SOURCES})

target_compile_features(recsrmesh PUBLIC cxx_std_20)

target_include_directories(recsrmesh PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MBEDTLS_INCLUDE_DIRS}
)

target_link_libraries(recsrmesh PUBLIC
    ${MBEDTLS_LIBRARIES}
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
