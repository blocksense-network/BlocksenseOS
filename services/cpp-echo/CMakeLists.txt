cmake_minimum_required(VERSION 3.20)
project(cpp-echo-service VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add the executable
add_executable(cpp-echo-service main.cpp)

# Install the executable
install(TARGETS cpp-echo-service
    RUNTIME DESTINATION bin
)