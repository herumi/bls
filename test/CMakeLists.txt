# BLS Tests
find_package(Threads REQUIRED)

add_executable(bls_c${bit}_test bls_c${bit}_test.cpp)
target_link_libraries(bls_c${bit}_test PRIVATE bls::bls${bit} Threads::Threads)
target_compile_definitions(bls_c${bit}_test PRIVATE BLS_DONT_EXPORT)
add_test(NAME bls_c${bit}_test COMMAND bls_c${bit}_test)

add_executable(bls${bit}_test bls${bit}_test.cpp)
target_link_libraries(bls${bit}_test PRIVATE bls::bls${bit} Threads::Threads)
target_compile_definitions(bls${bit}_test PRIVATE BLS_DONT_EXPORT)
add_test(NAME bls${bit}_test COMMAND bls${bit}_test)
