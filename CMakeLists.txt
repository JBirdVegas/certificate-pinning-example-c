cmake_minimum_required(VERSION 3.17)
project(ssl_pin_c VERSION 0.0.1 LANGUAGES C)
set(CMAKE_C_STANDARD 99)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(Json-C REQUIRED)

include_directories(/usr/local/include)
include_directories(/usr/local/opt/json-c/include)
link_directories(/usr/local/opt/json-c/lib)
include_directories(/usr/local/opt/openssl/include)

add_executable(ssl_pin_c main.c)

target_link_libraries(ssl_pin_c ${CURL_LIBRARIES})
target_link_libraries(ssl_pin_c OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(ssl_pin_c json-c)
