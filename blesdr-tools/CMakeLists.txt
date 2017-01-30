cmake_minimum_required(VERSION 2.8)
project(libblesdr CXX)
set(CMAKE_CXX_STANDARD 11)

find_package(LimeSuite REQUIRED)

include_directories(${LIMESUITE_INCLUDE_DIRS})
include_directories("../lib")

add_executable(blesdr blesdr.cpp "../lib/BLESDRDecoder.cpp" "../lib/BLESDREncoder.cpp")
target_link_libraries(blesdr ${LIMESUITE_LIBRARIES})

if(MSVC)
include_directories("getopt")
endif()

