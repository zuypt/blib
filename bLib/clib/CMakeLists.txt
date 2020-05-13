cmake_minimum_required(VERSION 2.6)

if("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "x64")
	MESSAGE("++ 64 bit architecture") 
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/bin64)
else() 
	MESSAGE("++ 32 bit architecture") 
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/bin32)
endif()

project(winafl_util_srv)
add_library(winafl_util_srv SHARED winafl_util_srv.c)

project(winafl_util_cli)
add_library(winafl_util_cli SHARED winafl_util_cli.c)

