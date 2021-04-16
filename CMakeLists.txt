cmake_minimum_required(VERSION 3.16)
project(SecureTAA)

set(CMAKE_CXX_STANDARD 14)

add_executable(SecureTAA main.cpp BroadCastEncryption.cpp BroadCastEncryption.h)