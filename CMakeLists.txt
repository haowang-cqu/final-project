cmake_minimum_required(VERSION 3.0.0)
project(server VERSION 0.1.0)

add_executable(server server.c des.c des.h)
add_executable(test_des test_des.c des.c des.h)