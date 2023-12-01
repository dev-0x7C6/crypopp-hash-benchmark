cmake_minimum_required(VERSION 3.20)

project(cryptographic-hash-benchmark LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(benchmark REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(cryptopp REQUIRED IMPORTED_TARGET libcryptopp)

add_executable(cryptographic-hash-benchmark main.cpp)

target_link_libraries(cryptographic-hash-benchmark benchmark::benchmark
                      PkgConfig::cryptopp ZLIB::ZLIB OpenSSL::Crypto)

install(TARGETS cryptographic-hash-benchmark RUNTIME DESTINATION bin)
