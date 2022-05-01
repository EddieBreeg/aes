cmake_minimum_required(VERSION 3.2)
project(aes)

include_directories(include)

set(aes_sources
    src/luts.c
    src/aes.c
)

add_library(aes ${aes_sources})

add_executable(test test.c)
target_link_libraries(test aes)