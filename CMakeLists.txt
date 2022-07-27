cmake_minimum_required(VERSION 3.14)

project(cryptographic-hash-benchmark LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(benchmark REQUIRED)
add_executable(cryptographic-hash-benchmark main.cpp)

target_link_libraries(cryptographic-hash-benchmark benchmark::benchmark -lcryptopp -lz OpenSSL::Crypto)
install(TARGETS cryptographic-hash-benchmark RUNTIME DESTINATION bin)
