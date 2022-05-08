cmake_minimum_required(VERSION 3.2)
project(aes)

include_directories(include)

set(aes_sources
    src/luts.c
    src/aes.c
)
set(cpp_aes_sources
    src/luts.c
    src/aes.cpp
)

add_library(aes ${aes_sources})
add_library(cpp_aes ${cpp_aes_sources})

add_executable(test test.c)
target_link_libraries(test aes)
add_executable(cpp_test test.cpp)
target_link_libraries(cpp_test cpp_aes)
add_executable(luts luts_tests.c)
target_link_libraries(luts aes)