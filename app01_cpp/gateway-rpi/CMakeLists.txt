cmake_minimum_required(VERSION 3.16)
project(app01_gateway CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(gateway
  src/main.cpp
  src/FrameDecoder.cpp
  src/NodeRegistry.cpp
)

# SAST gate (AGENTS.md invariant): findings fail the build; never suppress.
target_compile_options(gateway PRIVATE
  -Wall -Wextra -Wpedantic -Werror -fanalyzer
)

enable_testing()
add_test(NAME selftest COMMAND gateway --selftest)
