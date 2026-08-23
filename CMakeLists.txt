cmake_minimum_required(VERSION 4.1)
project(rendezvous)

include_directories(protocol)

set(CMAKE_CXX_STANDARD 23)

add_executable(rendezvous main.cpp
)
