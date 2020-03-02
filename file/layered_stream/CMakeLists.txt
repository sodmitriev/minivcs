add_library(layered_stream layered_stream.h layered_stream_def.h layered_stream.c)

add_library(layered_stream_file file_stream.h file_stream.c)
target_link_libraries(layered_stream_file layered_stream)

add_library(layered_stream_crypto crypto_stream.h crypto_stream.c)
target_link_libraries(layered_stream_crypto layered_stream)

add_executable(layered_stream_test test.c layered_stream.h layered_stream_def.h layered_stream.c
                                   file_stream.h file_stream.c crypto_stream.h crypto_stream.c)