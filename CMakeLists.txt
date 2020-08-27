cmake_minimum_required (VERSION 3.8)
project(bls CXX ASM C)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

option(
    BLS_BUILD_TESTING
    "Build bls tests"
    OFF
)
option(
    BLS_BUILD_SAMPLE
    "Build bls sample code"
    OFF
)
option(
    BLS_ETH
    "Ethereum 2.0 spec"
    "OFF"
)

if(BLS_ETH)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DBLS_ETH")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")

if(MSVC)
    if(MSVC_RUNTIME_DLL)
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} /MD /W4 /Oy /Ox /EHsc /GS- /Zi /DNDEBUG /DNOMINMAX")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} /MDd /W4 /DNOMINMAX")
    else()
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} /MT /W4 /Oy /Ox /EHsc /GS- /Zi /DNDEBUG /DNOMINMAX")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} /MTd /W4 /DNOMINMAX")
    endif()
else()
    if("${CFLAGS_OPT_USER}" STREQUAL "")
        set(CFLAGS_OPT_USER "-O3 -DNDEBUG -march=native")
    endif()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat=2 -Wcast-qual -Wcast-align -Wwrite-strings -Wfloat-equal -Wpointer-arith ${CFLAGS_OPT_USER}")
    set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")
endif()

add_subdirectory(external/mcl)

add_library(bls256 SHARED src/bls_c256.cpp)
add_library(bls::bls256 ALIAS bls256)
target_compile_definitions(bls256 PUBLIC MCLBN_NO_AUTOLINK BLS_NO_AUTOLINK)
target_include_directories(bls256 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_DIR}/include>)
target_link_libraries(bls256 PUBLIC mcl::mclbn256)

add_library(bls384 SHARED src/bls_c384.cpp)
add_library(bls::bls384 ALIAS bls384)
target_compile_definitions(bls384 PUBLIC MCLBN_NO_AUTOLINK BLS_NO_AUTOLINK)
target_include_directories(bls384 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_DIR}/include>)
target_link_libraries(bls384 PUBLIC mcl::mclbn384)

add_library(bls384_256 SHARED src/bls_c384_256.cpp)
add_library(bls::bls384_256 ALIAS bls384_256)
target_compile_definitions(bls384_256 PUBLIC MCLBN_NO_AUTOLINK BLS_NO_AUTOLINK)
target_include_directories(bls384_256 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_DIR}/include>)
target_link_libraries(bls384_256 PUBLIC mcl::mclbn384_256)


install(TARGETS bls256 bls384 bls384_256
    EXPORT blsTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION lib)
install(DIRECTORY include/bls
    DESTINATION include)
install(EXPORT blsTargets
    FILE blsTargets.cmake
    NAMESPACE bls::
    DESTINATION lib/cmake/bls)

export(EXPORT blsTargets
    FILE blsTargets.cmake
    NAMESPACE bls::)
set(CMAKE_EXPORT_PACKAGE_REGISTERY ON)
export(PACKAGE bls)

# Tests
if((CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME OR BLS_BUILD_TESTING)
    AND BUILD_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()

# Sample code
if(BLS_BUILD_SAMPLE)
    add_subdirectory(sample)
endif()
