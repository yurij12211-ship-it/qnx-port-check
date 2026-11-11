cmake_minimum_required(VERSION 3.16)
project(sample C)
add_executable(server src/server.c)
# -lrt in a comment must not count
target_link_libraries(server rt pthread)
target_compile_options(server PRIVATE -march=native)
