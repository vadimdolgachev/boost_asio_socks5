#include <boost/asio.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/url/url_view.hpp>

#include <exception>
#include <iostream>
#include <string>
#include <list>
#include <charconv>
#include <string_view>

#include "common.h"

namespace net = boost::asio;

using net::ip::tcp;

using Buffer = std::array<std::uint8_t, 4 * 1024>;

namespace po = boost::program_options;

constexpr std::string_view CONNECT_RESPONSE_OK = "HTTP/1.1 200 OK\r\n\r\n";

net::awaitable<void> listenSocksProxy(std::unique_ptr<tcp::acceptor> acceptor,
                                      const std::string &socksAddr,
                                      std::uint16_t socksPort,
                                      const std::string &certPath);

net::awaitable<void> listenHttpProxy(std::unique_ptr<tcp::acceptor> acceptor,
                                     const std::string &socksAddr,
                                     std::uint16_t socksPort,
                                     const std::string &certPath);

int main(int argc, char *argv[]) {
    po::options_description desc("socks5 proxy");
    desc.add_options()
            ("help", "produce help message")
            ("port", po::value<std::uint16_t>()->default_value(0), "port")
            ("socks5_server_addr", po::value<std::string>()->default_value(""), "socks5_server_addr")
            ("socks5_server_port", po::value<std::uint16_t>()->default_value(0), "socks5_server_port")
            ("cert_path", po::value<std::string>()->default_value(""), "cert_path")
            ("http_port", po::value<std::uint16_t>()->default_value(0), "http_port");
    po::variables_map optionsVarsMap;
    po::store(po::parse_command_line(argc, argv, desc), optionsVarsMap);
    po::notify(optionsVarsMap);
    if (optionsVarsMap.count("help") > 0) {
        std::cout << desc << "\n";
        return 0;
    }
    try {
        net::io_context ioContext;
        if (const auto port = optionsVarsMap["port"].as<std::uint16_t>(); port != 0) {
            net::co_spawn(ioContext,
                          listenSocksProxy(std::make_unique<tcp::acceptor>(ioContext, tcp::endpoint(tcp::v4(), port)),
                                           optionsVarsMap["socks5_server_addr"].as<std::string>(),
                                           optionsVarsMap["socks5_server_port"].as<std::uint16_t>(),
                                           optionsVarsMap["cert_path"].as<std::string>()),
                          net::detached);
        }
        if (const auto port = optionsVarsMap["http_port"].as<std::uint16_t>(); port != 0) {
            net::co_spawn(ioContext,
                          listenHttpProxy(std::make_unique<tcp::acceptor>(ioContext, tcp::endpoint(tcp::v4(), port)),
                                          optionsVarsMap["socks5_server_addr"].as<std::string>(),
                                          optionsVarsMap["socks5_server_port"].as<std::uint16_t>(),
                                          optionsVarsMap["cert_path"].as<std::string>()),
                          net::detached);
        }

        std::cout << "socks5 ssl tunnel started\n";
        net::signal_set signals(ioContext, SIGINT, SIGTERM);
        signals.async_wait([&ioContext](auto, auto) { ioContext.stop(); });
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

net::awaitable<void> startSocksSession(tcp::socket clientSocket,
                                       const std::string &socksAddr,
                                       const std::uint16_t socksPort,
                                       const std::string &certPath) {
    using namespace net::experimental::awaitable_operators;
    tcp::socket socks5Server(clientSocket.get_executor());
    if (const auto [error] = co_await socks5Server.async_connect(
                {net::ip::address_v4::from_string(socksAddr), socksPort},
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

net::awaitable<void> listenSocksProxy(std::unique_ptr<tcp::acceptor> acceptor,
                                      const std::string &socksAddr,
                                      const std::uint16_t socksPort,
                                      const std::string &certPath) {
    using namespace std::chrono_literals;

    for (;;) {
        auto [error, client] = co_await acceptor->async_accept(net::as_tuple(net::use_awaitable));
        if (!error) {
            const auto executor = client.get_executor();
            net::co_spawn(executor, startSocksSession(std::move(client),
                                                      socksAddr,
                                                      socksPort,
                                                      certPath), net::detached);
        } else {
            std::cerr << "Accept failed: " << error.message() << '\n';
            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(100ms);
            co_await timer.async_wait(net::use_awaitable);
        }
    }
}

net::awaitable<net::ssl::stream<tcp::socket>> makeProxyConnection(const std::string_view host,
                                                const std::uint16_t port,
                                                const tcp::endpoint &socksProxyEndpoint,
                                                const std::string &certPath,
                                                net::any_io_executor executor) {
    tcp::socket socksSocket(executor);
    co_await socksSocket.async_connect(socksProxyEndpoint, net::use_awaitable);

    net::ssl::context context(net::ssl::context::tlsv13_client);
    context.set_options(net::ssl::context::default_workarounds |
                        net::ssl::context::no_sslv2 | net::ssl::context::no_sslv3 |
                        net::ssl::context::no_tlsv1_1 | net::ssl::context::no_tlsv1_2);
    context.use_certificate_chain_file(certPath);

    net::ssl::stream<tcp::socket> sslSocket(std::move(socksSocket), context);
    const auto [handshakeError] =
            co_await sslSocket.async_handshake(net::ssl::stream_base::client,
                                               net::as_tuple(net::use_awaitable));
    if (handshakeError) {
        throw std::runtime_error("Socks handshake error: " + handshakeError.message());
    }

    // greeting
    Buffer buffer;
    std::size_t cursor = 0;
    buffer[cursor] = socks5::VERSION;
    ++cursor;
    buffer[cursor] = 1; // size of authentication methods
    ++cursor;
    buffer[cursor] = socks5::AuthMethod::NoAuthRequired;
    co_await sslSocket.async_write_some(net::buffer(buffer, cursor + 1),
                                     net::use_awaitable);

    // check greeting response
    if (const std::size_t length = co_await sslSocket.async_read_some(net::buffer(buffer),
                                                                   net::use_awaitable);
            length != 2 || buffer[0] != socks5::VERSION || buffer[1] != socks5::AuthMethod::NoAuthRequired) {
        throw std::runtime_error("Socks authentication error");
    }

    // request
    cursor = 0;
    buffer[cursor] = socks5::VERSION;
    ++cursor;
    buffer[cursor] = socks5::CmdType::Connect; // command type
    ++cursor;
    buffer[cursor] = socks5::RESERVED_FIELD;
    ++cursor;
    buffer[cursor] = socks5::AddressType::DomainName; // address type
    ++cursor;
    buffer[cursor] = host.size();
    ++cursor;
    std::copy(host.begin(), host.end(), &buffer[cursor]);
    cursor += host.size();
    const std::uint16_t networkPort = htons(port);
    std::memcpy(&buffer[cursor], &networkPort, sizeof(networkPort));
    cursor += sizeof(networkPort);
    co_await sslSocket.async_write_some(net::buffer(buffer, cursor),
                                     net::use_awaitable);

    // check request response
    const std::size_t length = co_await sslSocket.async_read_some(net::buffer(buffer),
                                                               net::use_awaitable);
    if (length != 10 || buffer[0] != socks5::VERSION || buffer[1] != socks5::ReplyCode::Succeeded) {
        throw std::runtime_error("Socks connection error");
    }
    co_return sslSocket;
}

net::awaitable<void> startHttpProxySession(tcp::socket clientSocket,
                                           const tcp::endpoint &socksProxyEndpoint,
                                           const std::string &certPath) {
    try {
        std::string httpRequest;
        const auto httpRequestLength = co_await boost::asio::async_read_until(clientSocket,
                                                                              net::dynamic_buffer(httpRequest),
                                                                              "\r\n\r\n",
                                                                              net::use_awaitable);

        std::istringstream requestStream(httpRequest);
        requestStream.unsetf(std::ios_base::skipws);
        std::string methodHeader;
        std::getline(requestStream, methodHeader);
        std::vector<std::string_view> methodParams;
        boost::algorithm::split(methodParams, methodHeader, boost::algorithm::is_any_of(" "));

        if (methodParams.size() > 2) {
            const std::string_view methodName = methodParams[0];
            const std::string_view uri = {methodParams[1].begin(), methodParams[1].end()};
//            std::cout << "Uri=" << uri << '\n';
//            const auto protocolVersion = methodParams[2];

            if (methodName == "CONNECT") {
                std::vector<std::string_view> hostPort;
                boost::algorithm::split(hostPort, uri, boost::is_any_of(":"));
                if (hostPort.size() == 2) {
                    co_await clientSocket.async_write_some(net::buffer(CONNECT_RESPONSE_OK),
                                                           net::use_awaitable);
                    const std::string_view host = hostPort[0];
                    std::uint16_t port = 0;
                    std::from_chars(hostPort[1].begin(), hostPort[1].end(), port);
                    auto socksSocket = co_await makeProxyConnection(host,
                                                                    port,
                                                                    socksProxyEndpoint,
                                                                    certPath,
                                                                    clientSocket.get_executor());
                    using namespace net::experimental::awaitable_operators;
                    co_await (transfer(clientSocket, socksSocket) || transfer(socksSocket, clientSocket));
                }
            } else {
                const boost::urls::url_view url(uri);
                const std::string host = url.host();
                const std::uint16_t port = url.has_port() ? url.port_number() : 80;
                auto socksSocket = co_await makeProxyConnection(host,
                                                                port,
                                                                socksProxyEndpoint,
                                                                certPath,
                                                                clientSocket.get_executor());
                co_await socksSocket.async_write_some(
                        net::buffer(httpRequest, httpRequestLength),
                        net::use_awaitable);
                co_await transfer(socksSocket, clientSocket);
            }
        }
    } catch (const std::exception &exception) {
        std::cerr << "Error: " << exception.what() << '\n';
    }
    co_return;
}

net::awaitable<void> listenHttpProxy(std::unique_ptr<tcp::acceptor> acceptor,
                                     const std::string &socksAddr,
                                     const std::uint16_t socksPort,
                                     const std::string &certPath) {
    using namespace std::chrono_literals;
    for (;;) {
        auto [error, client] = co_await acceptor->async_accept(net::as_tuple(net::use_awaitable));
        if (!error) {
            const auto executor = client.get_executor();
            const auto socksProxyEndpoint = tcp::endpoint(net::ip::address_v4::from_string(socksAddr), socksPort);
            net::co_spawn(executor,
                          startHttpProxySession(std::move(client), socksProxyEndpoint, certPath),
                          net::detached);
        } else {
            std::cerr << "Accept failed: " << error.message() << '\n';
            net::steady_timer timer(acceptor->get_executor());
            timer.expires_after(100ms);
            co_await timer.async_wait(net::use_awaitable);
        }
    }
}