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

# AFL++ fuzz harness (Plan Phase 4, stretch). Opt-in and off by default so it
# never affects the required verify workflow (app01_cpp/CLAUDE.md); build
# with -DBUILD_FUZZER=ON and CMAKE_CXX_COMPILER=afl-clang-fast++.
#   cmake -S gateway-rpi -B gateway-rpi/build-fuzz -DBUILD_FUZZER=ON \
#         -DCMAKE_CXX_COMPILER=afl-clang-fast++
#   cmake --build gateway-rpi/build-fuzz --target fuzz_decoder
option(BUILD_FUZZER "Build the AFL++ decoder fuzz harness (needs afl-clang-fast++)" OFF)
if(BUILD_FUZZER)
  add_executable(fuzz_decoder
    fuzz/fuzz_decoder.cpp
    src/FrameDecoder.cpp
  )
  target_include_directories(fuzz_decoder PRIVATE src)
  target_compile_options(fuzz_decoder PRIVATE -Wall -Wextra -Wpedantic -Werror)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(fuzz_decoder PRIVATE -fanalyzer)
  endif()
endif()
