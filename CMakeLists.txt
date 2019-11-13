cmake_minimum_required(VERSION 2.6)
project(gothook)

if(BUILD_32)
  set(CMAKE_C_FLAGS "-m32")
  set(CMAKE_CXX_FLAGS "-m32")
endif()

if(BUILD_64)
  set(CMAKE_C_FLAGS "-m64")
  set(CMAKE_CXX_FLAGS "-m64")
endif()

add_library(gothook STATIC
  gothook.cpp
  gothook.h
)

if(TEST)
  add_executable(test test.cpp)
  target_link_libraries(test gothook -ldl)
endif()