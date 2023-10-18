cmake_minimum_required(VERSION 3.26)
project(socks5_server)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system program_options)

set(CMAKE_CXX_STANDARD 20)

set(COMPILE_FLAGS
            -Wall
            -Wpedantic
            -Wextra
            -Werror=unused-result
            -Werror=return-type
            -Wfloat-equal)

add_compile_definitions(
        $<$<CONFIG:DEBUG>:BOOST_ASIO_ENABLE_BUFFER_DEBUGGING>
#        $<$<CONFIG:DEBUG>:BOOST_ASIO_ENABLE_HANDLER_TRACKING>
)

add_subdirectory(socks5_ssl_tunnel)

add_executable(socks5_server main.cpp common.h)
target_compile_options(socks5_server PRIVATE ${COMPILE_FLAGS})
target_link_libraries(socks5_server PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::system
        Boost::program_options)
