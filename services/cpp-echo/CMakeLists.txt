cmake_minimum_required(VERSION 3.20)
project(cpp-echo-service VERSION 0.2.0)

# Enforce out-of-source builds
if(CMAKE_BINARY_DIR STREQUAL CMAKE_SOURCE_DIR)
    message(FATAL_ERROR "In-source builds are not allowed. Please create a separate build directory.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Threads REQUIRED)

# Find standalone ASIO (provided by Nix)
find_path(ASIO_INCLUDE_DIR asio.hpp PATHS $ENV{ASIO_ROOT}/include /usr/include /usr/local/include)
if(ASIO_INCLUDE_DIR)
    message(STATUS "Found standalone ASIO at ${ASIO_INCLUDE_DIR}")
    add_definitions(-DASIO_STANDALONE)
    add_definitions(-DASIO_HAS_CO_AWAIT)
else()
    message(FATAL_ERROR "Standalone ASIO not found. Please ensure it's available in the Nix environment.")
endif()

# Compiler flags for modern C++, security and performance
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines")  # Enable coroutines

# Add the executable
add_executable(cpp-echo-service main.cpp)

# Link libraries
target_link_libraries(cpp-echo-service Threads::Threads)
target_include_directories(cpp-echo-service PRIVATE ${ASIO_INCLUDE_DIR})

# Install the executable
install(TARGETS cpp-echo-service
    RUNTIME DESTINATION bin
)