cmake_minimum_required(VERSION 3.26)
project(boost_asio_socks5)

find_package(Boost REQUIRED COMPONENTS system)

set(CMAKE_CXX_STANDARD 20)

add_executable(boost_asio_socks5 main.cpp)
target_link_libraries(boost_asio_socks5 PRIVATE Boost::system)