cmake_minimum_required(VERSION 3.16)
project(echo_server C)
set(CMAKE_C_STANDARD 99)
add_executable(echo-server server.c)

find_package(Threads REQUIRED)
target_link_libraries(echo-server Threads::Threads)

if(QNX)
  # BSD sockets live in libsocket on QNX; rt/dl/pthread are part of libc
  target_link_libraries(echo-server socket)
endif()
