cmake_minimum_required(VERSION 3.5)

# Set the project name
project (unwind_samples)

set(UNWIND_INSTALL_DIR ${PROJECT_SOURCE_DIR}/../install)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g ")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}  -Wl")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -g")

link_directories(${UNWIND_INSTALL_DIR}/include)
link_libraries(${UNWIND_INSTALL_DIR}/lib)

add_executable(unwind_samples main.cpp)
target_link_libraries(unwind_samples PUBLIC unwind unwind-x86_64)
