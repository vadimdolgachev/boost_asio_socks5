cmake_minimum_required(VERSION 3.26)
project(boost_asio_socks5)

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

add_executable(boost_asio_socks5 main.cpp common.h)
target_compile_options(boost_asio_socks5 PRIVATE ${COMPILE_FLAGS})
target_link_libraries(boost_asio_socks5 PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::system
        Boost::program_options)
