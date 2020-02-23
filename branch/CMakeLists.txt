add_library(files files.h files.c)
target_link_libraries(files config)
add_library(branch branch.h branch.c)
target_link_libraries(branch files)