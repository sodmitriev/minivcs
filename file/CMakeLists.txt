find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_libraries(${OPENSSL_LIBRARIES})

add_library(crypt crypt.h crypt.c)
add_library(hash hash.h hash.c)
add_library(compress compress.h compress.c)
add_library(encode encode.h encode.c)
add_executable(crypto_test test.c crypt.h crypt.c hash.h hash.c compress.h compress.c encode.h encode.c)