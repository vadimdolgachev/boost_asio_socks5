cmake_minimum_required(VERSION 3.26)
project(socks5_ssl_tunnel)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system program_options url)

set(CMAKE_CXX_STANDARD 20)

add_executable(socks5_ssl_tunnel main.cpp ../common.h)
target_compile_options(socks5_ssl_tunnel PRIVATE ${COMPILE_FLAGS})
target_include_directories(socks5_ssl_tunnel PUBLIC "../")
target_link_libraries(socks5_ssl_tunnel PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::system
        Boost::program_options
        Boost::url
)
