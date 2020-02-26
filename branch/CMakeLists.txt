add_library(file_name name.h name.c)
target_link_libraries(file_name encode)

add_library(file_storage storage.h storage.c)

add_library(files files.h files.c)
target_link_libraries(files file_name file_storage config hash)

add_library(branch branch.h branch.c)
target_link_libraries(branch files)

add_executable(branch_test test.c files.h files.c branch.h branch.c name.h name.c storage.h storage.c)
target_link_libraries(branch_test config encode hash)