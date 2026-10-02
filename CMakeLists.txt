cmake_minimum_required(VERSION 3.21)
project(entra_auditor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(CURL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(entra_auditor src/main.cpp src/http.cpp src/token.cpp src/graph.cpp src/audit.cpp)
target_link_libraries(entra_auditor PRIVATE CURL::libcurl nlohmann_json::nlohmann_json)
