cmake_minimum_required(VERSION 3.15)
project(minivcs C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-Wall -Wextra -Wpedantic -Wcast-align -Wcast-qual -Wconversion -Wenum-compare -Wredundant-decls\
                   -Wno-sign-conversion ${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 ${CMAKE_C_FLAGS_DEBUG}")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG ${CMAKE_C_FLAGS_RELEASE}")

include_directories(.)
include_directories(uthash/include)
include_directories(CTransform)

add_subdirectory(CTransform)
add_subdirectory(file)
add_subdirectory(config)
add_subdirectory(branch)

add_library(minivcs_project minivcs.h minivcs.c)
target_link_libraries(minivcs_project branch)

add_executable(minivcs main.c)
target_link_libraries(minivcs minivcs_project)