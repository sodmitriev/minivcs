add_library(crypt crypt.h crypt.c)
add_library(hash hash.h hash.c)
add_library(compress compress.h compress.c)
add_executable(crypto_test test.c crypt.h crypt.c hash.h hash.c compress.h compress.c)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(crypto_test ${OPENSSL_LIBRARIES})