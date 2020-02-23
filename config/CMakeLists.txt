add_library(config config.h config.c)
add_executable(config_test test.c config.h config.c)