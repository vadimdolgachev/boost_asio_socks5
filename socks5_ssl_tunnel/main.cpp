#include <boost/asio.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/program_options.hpp>

#include <exception>
#include <iostream>
#include <string>

namespace net = boost::asio;

using net::ip::tcp;

using Buffer = std::array<std::uint8_t, 4 * 1024>;

namespace po = boost::program_options;

net::awaitable<void> listen(tcp::acceptor &acceptor,
                            const std::string &socks5Addr,
                            std::uint16_t socks5Port,
                            const std::string &certPath);

int main(int argc, char *argv[]) {
    po::options_description desc("socks5 proxy");
    desc.add_options()
            ("help", "produce help message")
            ("port", po::value<std::uint16_t>()->default_value(0), "port")
            ("socks5_server_addr", po::value<std::string>()->default_value(""), "socks5_server_addr")
            ("socks5_server_port", po::value<std::uint16_t>()->default_value(0), "socks5_server_port")
            ("cert_path", po::value<std::string>()->default_value(""), "cert_path");
    po::variables_map optionsVarsMap;
    po::store(po::parse_command_line(argc, argv, desc), optionsVarsMap);
    po::notify(optionsVarsMap);
    if (optionsVarsMap.count("help") > 0) {
        std::cout << desc << "\n";
        return 0;
    }
    try {
        net::io_context ioContext;
        tcp::acceptor acceptor(ioContext, tcp::endpoint(tcp::v4(),
                                                        optionsVarsMap["port"].as<std::uint16_t>()));
        net::co_spawn(ioContext, listen(acceptor,
                                        optionsVarsMap["socks5_server_addr"].as<std::string>(),
                                        optionsVarsMap["socks5_server_port"].as<std::uint16_t>(),
                                        optionsVarsMap["cert_path"].as<std::string>()), net::detached);
        std::cout << "socks5 ssl tunnel started" << std::endl;
        ioContext.run();
    } catch (std::exception &e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}

template<typename ReadableSocketType, typename WritableSocketType>
net::awaitable<void> transfer(ReadableSocketType &readableSocket, WritableSocketType &writableSocket) {
    Buffer data = {};
    for (;;) {
        const auto [readError, readLength] = co_await readableSocket.async_read_some(net::buffer(data),
                                                                                     net::as_tuple(net::use_awaitable));
        if (readError) {
            break;
        }
        const auto [writeError, writeLength] = co_await net::async_write(writableSocket, net::buffer(data, readLength),
                                                                         net::as_tuple(net::use_awaitable));
        if (writeError) {
            break;
        }
    }
}

net::awaitable<void> startSession(tcp::socket clientSocket,
                                  const std::string &socks5Addr,
                                  const std::uint16_t socks5Port,
                                  const std::string &certPath) {
    using namespace net::experimental::awaitable_operators;
    tcp::socket socks5Server(clientSocket.get_executor());
    if (const auto [error] = co_await socks5Server.async_connect(
                {net::ip::address_v4::from_string(socks5Addr), socks5Port},
                net::as_tuple(net::use_awaitable)); !error) {
        net::ssl::context context(net::ssl::context::tlsv13_client);
        context.set_options(net::ssl::context::default_workarounds |
                            net::ssl::context::no_sslv2 | net::ssl::context::no_sslv3 |
                            net::ssl::context::no_tlsv1_1 | net::ssl::context::no_tlsv1_2);
        context.use_certificate_chain_file(certPath);

        net::ssl::stream<tcp::socket> sslSocket(std::move(socks5Server), context);
        const auto [handshakeError] =
                co_await sslSocket.async_handshake(net::ssl::stream_base::client,
                                                   net::as_tuple(net::use_awaitable));
        if (!handshakeError) {
            co_await (transfer(clientSocket, sslSocket) || transfer(sslSocket, clientSocket));
        } else {
            std::cerr << "Handshake error: " << handshakeError.message() << '\n';
        }
        const auto [errorShutdown] = co_await sslSocket.async_shutdown(net::as_tuple(net::use_awaitable));
        if (errorShutdown) {
            std::cerr << "Shutdown error: " << errorShutdown.message() << '\n';
        }
    } else {
        std::cerr << "Connection error: " << error.message() << '\n';
    }
}

net::awaitable<void> listen(tcp::acceptor &acceptor,
                            const std::string &socks5Addr,
                            const std::uint16_t socks5Port,
                            const std::string &certPath) {
    using namespace std::chrono_literals;

    for (;;) {
        auto [error, client] = co_await acceptor.async_accept(net::as_tuple(net::use_awaitable));
        if (!error) {
            const auto executor = client.get_executor();
            net::co_spawn(executor, startSession(std::move(client),
                                                 socks5Addr,
                                                 socks5Port,
                                                 certPath), net::detached);
        } else {
            std::cerr << "Accept failed: " << error.message() << '\n';
            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(100ms);
            co_await timer.async_wait(net::use_awaitable);
        }
    }
}