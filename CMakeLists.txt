cmake_minimum_required (VERSION 2.6)
project(bls CXX ASM)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(LIBS mcl gmp)

include_directories(include/)

add_library(bls_c256 SHARED src/bls_c256.cpp)
add_library(bls_c384 SHARED src/bls_c384.cpp)
add_library(bls_c384_256 SHARED src/bls_c384_256.cpp)
target_link_libraries(bls_c256 ${LIBS})
target_link_libraries(bls_c384 ${LIBS})
target_link_libraries(bls_c384_256 ${LIBS})

file(GLOB BLS_HEADERS include/bls/bls.h include/bls/bls.hpp)

install(TARGETS bls_c256 DESTINATION lib)
install(TARGETS bls_c384 DESTINATION lib)
install(TARGETS bls_c384_256 DESTINATION lib)
install(FILES ${BLS_HEADERS} DESTINATION include/bls)

set(TEST_LIBS pthread gmpxx)

add_executable(bls_c256_test test/bls_c256_test.cpp)
target_link_libraries(bls_c256_test bls_c256 ${TEST_LIBS})
add_executable(bls_c384_test test/bls_c384_test.cpp)
target_link_libraries(bls_c384_test bls_c384 ${TEST_LIBS})
add_executable(bls_c384_256_test test/bls_c384_256_test.cpp)
target_link_libraries(bls_c384_256_test bls_c384_256 ${TEST_LIBS})
