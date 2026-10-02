cmake_minimum_required(VERSION 3.21)
project(entra_auditor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(CURL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(entra_auditor src/main.cpp src/http.cpp src/token.cpp src/graph.cpp src/audit.cpp src/report.cpp src/guard.cpp src/time_util.cpp)
target_link_libraries(entra_auditor PRIVATE CURL::libcurl nlohmann_json::nlohmann_json)

# Tests: build with `cmake --build build`, run with `ctest --test-dir build`
enable_testing()
add_executable(tests tests/tests.cpp src/audit.cpp src/graph.cpp src/http.cpp src/guard.cpp src/time_util.cpp)
target_link_libraries(tests PRIVATE CURL::libcurl nlohmann_json::nlohmann_json)
add_test(NAME unit COMMAND tests)
