add_library(file_transformation_context file_transformation_context.h file_transformation_context.c)
target_link_libraries(file_transformation_context config)

add_library(file_transformation_controller file_transformation_controller.h file_transformation_controller.c)
target_link_libraries(file_transformation_controller file_transformation_context controller
                                                     transformation_encrypt transformation_decrypt
                                                     transformation_compress transformation_decompress)

add_library(file_operations operations.h operations.c)
target_link_libraries(file_operations file_transformation_controller transformation_b64_encode transformation_replace
                                      transformation_hash source_write sink_read source_file sink_file)

add_executable(file_operations_test test.c)
target_link_libraries(file_operations_test file_operations)