add_library(file_storage storage.h storage.c)
target_link_libraries(file_storage CEasyException)

add_library(files files.h files.c)
target_link_libraries(files file_storage file_operations)

add_library(branch branch.h branch.c)
target_link_libraries(branch files sink_gets)

add_executable(branch_test test.c files.h files.c branch.h branch.c storage.h storage.c)
target_link_libraries(branch_test config file_operations sink_gets)