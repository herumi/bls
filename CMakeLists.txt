cmake_minimum_required (VERSION 2.6)
project(bls CXX ASM C)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(LIBS mcl gmp)

option(
	BLS_SWAP_G
	"swap G1 and G2"
	"OFF"
)
option(
	BLS_ETH
	"Ethereum 2.0 spec"
	"OFF"
)

if(BLS_SWAP_G)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DBLS_SWAP_G")
endif()

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

set(TEST_LIBS gmpxx)

add_executable(bls_c256_test test/bls_c256_test.cpp)
target_link_libraries(bls_c256_test bls_c256 ${TEST_LIBS})
add_executable(bls_c384_test test/bls_c384_test.cpp)
target_link_libraries(bls_c384_test bls_c384 ${TEST_LIBS})
add_executable(bls_c384_256_test test/bls_c384_256_test.cpp)
target_link_libraries(bls_c384_256_test bls_c384_256 ${TEST_LIBS})

add_executable(minsample sample/minsample.c)
target_link_libraries(minsample bls_c384_256)
