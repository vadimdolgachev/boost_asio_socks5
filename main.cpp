#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/detail/error_code.hpp>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/asio/ssl.hpp>

#include <netinet/in.h>

#include <memory>
#include <exception>
#include <iostream>
#include <string_view>
#include <unordered_set>

#include "common.h"

namespace po = boost::program_options;

namespace net = boost::asio;

using net::ip::tcp;

using Buffer = std::vector<std::uint8_t>;

template<typename ValType, typename EnumType>
concept isEnumType = std::same_as<ValType, std::underlying_type_t<EnumType>>;

template<typename EnumType, EnumType... EnumMembers>
struct EnumCheck {
    template<typename ValueType>
    requires isEnumType<ValueType, EnumType>
    static constexpr bool isValue(const ValueType /*value*/) { return false; }
};

template<typename EnumType, EnumType EnumMem, EnumType... NextEnumMem>
struct EnumCheck<EnumType, EnumMem, NextEnumMem...> : private EnumCheck<EnumType, NextEnumMem...> {
    template<typename ValueType>
    requires isEnumType<ValueType, EnumType>
    static constexpr bool isValue(const ValueType value) {
        return value == static_cast<ValueType>(EnumMem) || EnumCheck<EnumType, NextEnumMem...>::isValue(value);
    }
};

enum class State {
    Greeting,
    UserPassRequest,
    Request,
    Transfer,
    EndOfSession
};

using AuthMethodCheck = EnumCheck<socks5::AuthMethod,
        socks5::AuthMethod::UsernamePassword,
        socks5::AuthMethod::NoAuthRequired,
        socks5::AuthMethod::GSSAPI>;

net::awaitable<void> listen(std::unique_ptr<tcp::acceptor> acceptor,
                            const std::string &username,
                            const std::string &password);

net::awaitable<void> listenSsl(std::unique_ptr<tcp::acceptor> acceptor,
                               const std::string &username,
                               const std::string &password,
                               const std::string &certPath,
                               const std::string &privateKeyPath,
                               const std::string &dhKeyPath);

int main(int argc, char *argv[]) {
    po::options_description desc("socks5 proxy");
    desc.add_options()
            ("help", "produce help message")
            ("port", po::value<std::uint16_t>()->default_value(0), "port")
            ("ssl_port", po::value<std::uint16_t>()->default_value(0), "ssl_port")
            ("cert_path", po::value<std::string>()->default_value(""), "cert_path")
            ("private_key_path", po::value<std::string>()->default_value(""), "private_key_path")
            ("dh_key_path", po::value<std::string>()->default_value(""), "dh_key_path")
            ("username", po::value<std::string>()->default_value(""), "username")
            ("password", po::value<std::string>()->default_value(""), "password");
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
            net::co_spawn(ioContext, listen(std::make_unique<tcp::acceptor>(ioContext,
                                                                            tcp::endpoint(tcp::v4(), port)),
                                            optionsVarsMap["username"].as<std::string>(),
                                            optionsVarsMap["password"].as<std::string>()), net::detached);

        }
        if (const auto sslPort = optionsVarsMap["ssl_port"].as<std::uint16_t>(); sslPort != 0) {
            net::co_spawn(ioContext, listenSsl(std::make_unique<tcp::acceptor>(ioContext,
                                                                               tcp::endpoint(tcp::v4(), sslPort)),
                                               optionsVarsMap["username"].as<std::string>(),
                                               optionsVarsMap["password"].as<std::string>(),
                                               optionsVarsMap["cert_path"].as<std::string>(),
                                               optionsVarsMap["private_key_path"].as<std::string>(),
                                               optionsVarsMap["dh_key_path"].as<std::string>()),
                          net::detached);

        }
        std::cout << "Server started\n";

        net::signal_set signals(ioContext, SIGINT, SIGTERM);
        signals.async_wait([&ioContext](auto, auto) { ioContext.stop(); });
        ioContext.run();
    } catch (std::exception &e) {
        std::cerr << "Exception: " << e.what() << '\n';
    }
    return 0;
}

std::tuple<State, std::size_t> onGreeting(Buffer &data, const std::size_t length, const bool isEmptyUsername) {
    constexpr std::size_t minLength = 3;
    std::size_t cursor = 0;
    if (length < minLength || data[cursor] != socks5::VERSION) {
        return std::make_tuple(State::EndOfSession, 0);
    }
    cursor += 1;
    const std::size_t authMethodLength = data[cursor];
    if (cursor + authMethodLength > length) {
        return std::make_tuple(State::EndOfSession, 0);
    }

    std::unordered_set<socks5::AuthMethod> authMethods;
    for (std::size_t i = 0; i < authMethodLength; ++i) {
        cursor += 1;
        if (const auto value = data[cursor]; AuthMethodCheck::isValue(value)) {
            authMethods.insert(static_cast<socks5::AuthMethod>(value));
        }
    }

    const auto selectedAuthMethod = authMethods.contains(socks5::AuthMethod::UsernamePassword) || !isEmptyUsername
                                    ? socks5::AuthMethod::UsernamePassword : socks5::AuthMethod::NoAuthRequired;
    constexpr std::size_t responseLength = 2;
    data[0] = socks5::VERSION;
    data[1] = selectedAuthMethod;
    return std::make_tuple(selectedAuthMethod == socks5::AuthMethod::UsernamePassword
                           ? State::UserPassRequest : State::Request, responseLength);
}

std::tuple<State, std::size_t> onUserPassRequest(Buffer &data,
                                                 const std::size_t length,
                                                 const std::string &username,
                                                 const std::string &password) {
    std::size_t cursor = 0;
    if (data[cursor] != socks5::AUTH_METHOD_VERSION) {
        return std::make_tuple(State::EndOfSession, 0);
    }
    cursor += 1;

    const auto clientUsernameLength = data[cursor];
    cursor += 1;
    if (cursor + clientUsernameLength > length) {
        return std::make_tuple(State::EndOfSession, 0);
    }
    const std::string_view clientUsername(reinterpret_cast<char *>(&data[cursor]), clientUsernameLength);

    cursor += clientUsernameLength;
    const auto clientPasswordLength = data[cursor];
    cursor += 1;
    if (cursor + clientPasswordLength > length) {
        return std::make_tuple(State::EndOfSession, 0);
    }
    const std::string_view clientPassword(reinterpret_cast<char *>(&data[cursor]), clientPasswordLength);

    constexpr std::size_t responseLength = 2;
    data[0] = socks5::AUTH_METHOD_VERSION;
    const bool isSuccessful = (username == clientUsername && (password.empty() || password == clientPassword));
    data[1] = isSuccessful ? socks5::AuthStatusReply::Successful : socks5::AuthStatusReply::Failure;
    return std::make_tuple(isSuccessful ? State::Request : State::EndOfSession, responseLength);
}

net::awaitable<std::tuple<State, std::unique_ptr<tcp::socket>, std::size_t>>
onRequest(const tcp::socket::executor_type &executor,
          const tcp::endpoint &serverEndpoint,
          Buffer &data) {
    if (data[0] != socks5::VERSION) {
        co_return std::make_tuple(State::EndOfSession, nullptr, 0);
    }

    std::optional<tcp::endpoint> targetEndpoint;
    auto replyCode = socks5::ReplyCode::Succeeded;

    const auto addressType = data[3];
    if (addressType == socks5::AddressType::IpV4) {
        net::ip::port_type targetPort = 0;
        std::memcpy(&targetPort, &data[8], sizeof(targetPort));
        targetEndpoint = tcp::endpoint(net::ip::address_v4({data[4],
                                                            data[5],
                                                            data[6],
                                                            data[7]}), ntohs(targetPort));
    } else if (addressType == socks5::AddressType::DomainName) {
        const std::size_t hostNameLength = data[4];
        tcp::resolver resolver(executor);
        net::ip::port_type targetPort = 0;
        std::memcpy(&targetPort, &data[5] + hostNameLength, sizeof(targetPort));
        const std::string_view hostName(reinterpret_cast<char *>(&data[5]), hostNameLength);
        const auto [error, endpoints] = co_await resolver.async_resolve(
                hostName,
                std::to_string(ntohs(targetPort)),
                net::as_tuple(net::use_awaitable));
        if (error) {
            std::cerr << hostName << "-" << error.message() << '\n';
            replyCode = socks5::ReplyCode::HostUnreachable;
        } else {
            targetEndpoint = *endpoints.begin();
        }
    } else {
        replyCode = socks5::ReplyCode::AddressTypeNotSupported;
    }

    std::unique_ptr<tcp::socket> targetSocket = nullptr;

    if (targetEndpoint) {
        const auto cmdType = data[1];
        if (cmdType == socks5::CmdType::Connect) {
            targetSocket = std::make_unique<tcp::socket>(executor);
            const auto [error] = co_await targetSocket->async_connect(*targetEndpoint,
                                                                      net::as_tuple(net::use_awaitable));
            switch (error.value()) {
                case net::error::network_unreachable:
                    replyCode = socks5::ReplyCode::NetworkUnreachable;
                    break;
                case net::error::connection_refused:
                    replyCode = socks5::ReplyCode::ConnectionRefused;
                    break;
                default:
                    break;
            }
            if (error) {
                std::cerr << *targetEndpoint << "-" << error.message() << '\n';
            }
        } else {
            replyCode = socks5::ReplyCode::CommandNotSupported;
        }
    }

    data[0] = socks5::VERSION;
    data[1] = replyCode;
    data[2] = socks5::RESERVED_FIELD;
    data[3] = socks5::AddressType::IpV4;

    const auto addrBytes = serverEndpoint.address().to_v4().to_bytes();
    static_assert(std::size(addrBytes) == 4);
    std::copy(std::begin(addrBytes), std::end(addrBytes), &data[4]);

    const auto serverPort = htons(serverEndpoint.port());
    static_assert(sizeof(serverPort) == 2);
    std::memcpy(&data[8], &serverPort, sizeof(serverPort));

    co_return std::make_tuple(replyCode == socks5::ReplyCode::Succeeded ? State::Transfer : State::EndOfSession,
                              std::move(targetSocket),
                              socks5::REPLY_LENGTH_FOR_REQUEST);
}

template<typename SocketType>
net::awaitable<std::tuple<State, std::size_t>> onTransfer(SocketType &clientSocket,
                                                          tcp::socket &targetSocket,
                                                          const Buffer &data,
                                                          const std::size_t length) {
    using namespace net::experimental::awaitable_operators;

    co_await net::async_write(targetSocket, net::buffer(data, length), net::use_awaitable);
    co_await (transfer(clientSocket, targetSocket) || transfer(targetSocket, clientSocket));
    co_return std::make_tuple(State::EndOfSession, 0);
}

template<typename SocketType>
requires (std::same_as<SocketType, net::ssl::stream<tcp::socket>> || std::same_as<SocketType, tcp::socket>)
const auto &toTcpSocket(const SocketType &socket) {
    if constexpr (std::same_as<SocketType, net::ssl::stream<tcp::socket>>) {
        return socket.lowest_layer();
    } else if (std::same_as<SocketType, tcp::socket>) {
        return socket;
    }
}

template<typename SocketType>
net::awaitable<void> startSession(SocketType client,
                                  const std::string &username,
                                  const std::string &password) {
    State state = State::Greeting;
    Buffer data(4 * 1024);
    std::unique_ptr<tcp::socket> targetSocket;

    try {
        for (;;) {
            auto [error, length] = co_await client.async_read_some(net::buffer(data),
                                                                   net::as_tuple(net::use_awaitable));
            if (error == net::error::eof) {
                state = State::EndOfSession;
            } else if (error) {
                throw boost::system::system_error(error);
            }

            switch (state) {
                case State::Greeting:
                    std::tie(state, length) = onGreeting(data, length, username.empty());
                    break;
                case State::Request:
                    std::tie(state, targetSocket, length)
                            = co_await onRequest(client.get_executor(), toTcpSocket(client).local_endpoint(), data);
                    break;
                case State::UserPassRequest:
                    std::tie(state, length) = onUserPassRequest(data, length, username, password);
                    break;
                case State::Transfer:
                    if (targetSocket) {
                        std::tie(state, length) = co_await onTransfer(client, *targetSocket, data, length);
                    } else {
                        state = State::EndOfSession;
                        length = 0;
                    }
                    break;
                default:
                    break;
            }

            if (length > 0) {
                co_await net::async_write(client, net::buffer(data, length), net::use_awaitable);
            }
            if (state == State::EndOfSession) {
                break;
            }
        }
    } catch (const std::exception &e) {
        std::cerr << "Proxy error: " << e.what() << "\n";
    }
}

net::awaitable<void> listenSsl(std::unique_ptr<tcp::acceptor> acceptor,
                               const std::string &username,
                               const std::string &password,
                               const std::string &certPath,
                               const std::string &privateKeyPath,
                               const std::string &dhKeyPath) {
    using namespace std::chrono_literals;

    for (;;) {
        auto [error, clientSocket] = co_await acceptor->async_accept(net::as_tuple(net::use_awaitable));
        if (!error) {
            const auto executor = clientSocket.get_executor();
            net::ssl::context context(net::ssl::context::tlsv13_server);
            context.set_options(net::ssl::context::default_workarounds |
                                net::ssl::context::no_sslv2 | net::ssl::context::no_sslv3 |
                                net::ssl::context::no_tlsv1_1 | net::ssl::context::no_tlsv1_2 |
                                net::ssl::context::single_dh_use);
            context.use_certificate_chain_file(certPath);
            context.use_private_key_file(privateKeyPath, net::ssl::context::pem);
            context.use_tmp_dh_file(dhKeyPath);

            net::ssl::stream<tcp::socket> sslClientSocket(std::move(clientSocket), context);
            const auto [handshakeError] =
                    co_await sslClientSocket.async_handshake(net::ssl::stream_base::server,
                                                             net::as_tuple(net::use_awaitable));
            if (!handshakeError) {
                net::co_spawn(executor,
                              startSession(std::move(sslClientSocket), username, password),
                              net::detached);
            } else {
                std::cerr << "Handshake error: " << handshakeError.message() << '\n';
            }
        } else {
            std::cerr << "Accept failed: " << error.message() << "\n";
            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(100ms);
            co_await timer.async_wait(net::use_awaitable);
        }
    }
}

net::awaitable<void> listen(std::unique_ptr<tcp::acceptor> acceptor,
                            const std::string &username,
                            const std::string &password) {
    using namespace std::chrono_literals;

    for (;;) {
        auto [error, clientSocket] = co_await acceptor->async_accept(net::as_tuple(net::use_awaitable));
        if (!error) {
            const auto executor = clientSocket.get_executor();
            net::co_spawn(executor,
                          startSession(std::move(clientSocket), username, password),
                          net::detached);
        } else {
            std::cerr << "Accept failed: " << error.message() << "\n";
            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(100ms);
            co_await timer.async_wait(net::use_awaitable);
        }
    }
}
