cmake_minimum_required(VERSION 4.1)
project(rendezvous)

include_directories(protocol)

find_package(OpenSSL REQUIRED)


set(CMAKE_CXX_STANDARD 23)

add_executable(rendezvous main.cpp
        protocol/rendezvous_codec.cpp
        protocol/rendezvous_codec.h
        protocol/security/hmac_utils.h
        protocol/security/hmac_utils.cpp
)

target_link_libraries(rendezvous PRIVATE    OpenSSL::Crypto)