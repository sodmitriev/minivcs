add_library(config config.h config.c)
target_link_libraries(config CEasyException)

add_executable(config_test test.c config.h config.c)
target_link_libraries(config_test CEasyException)