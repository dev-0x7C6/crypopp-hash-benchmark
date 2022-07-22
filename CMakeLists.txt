cmake_minimum_required(VERSION 3.14)

project(cryptopp-hash-benchmark LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(benchmark REQUIRED)
add_executable(cryptopp-hash-benchmark main.cpp)

target_link_libraries(cryptopp-hash-benchmark benchmark::benchmark -lcryptopp OpenSSL::Crypto)
install(TARGETS cryptopp-hash-benchmark RUNTIME DESTINATION bin)
