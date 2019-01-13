cmake_minimum_required(VERSION 2.6)
project (functrace)

add_library(functrace SHARED functrace.cpp bb_getinfo.cpp)
find_package(DynamoRIO)
configure_DynamoRIO_client(functrace)

use_DynamoRIO_extension(functrace drmgr)
use_DynamoRIO_extension(functrace drsyms)
use_DynamoRIO_extension(functrace drwrap)

if (NOT DynamoRIO_FOUND)
	  message(FATAL_ERROR "DynamoRIO package required to build")
  endif(NOT DynamoRIO_FOUND)
