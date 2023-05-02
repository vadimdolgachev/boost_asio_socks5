#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/detail/error_code.hpp>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <exception>
#include <iostream>
#include <netinet/in.h>
#include <string_view>

namespace net = boost::asio;

using net::ip::tcp;

using Buffer = std::array<std::uint8_t, 4 * 1024>;

constexpr std::uint8_t SOCKS_VER = 5;
constexpr std::uint8_t RESERVED_FIELD = 0;

enum class State {
    Greeting,
    Request,
    Transfer,
    EndOfSession
};

enum AuthMethod : std::uint8_t {
    NoAuthRequired = 0,
    UserNamePassword = 2
};

enum CmdType : std::uint8_t {
    Connect = 1,
    Bind = 2,
    Udp = 3
};

enum AddressType : std::uint8_t {
    IpV4 = 1,
    IpV6 = 4,
    DomainName = 3,
};

enum ReplyCode : std::uint8_t {
    Succeeded = 0,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8
};

net::awaitable<void> listen(tcp::acceptor &acceptor);

int main() {
    try {
        net::io_context ioContext;

        tcp::acceptor acceptor(ioContext, tcp::endpoint(tcp::v4(), 10800));
        net::co_spawn(ioContext, listen(acceptor), net::detached);
        ioContext.run();
    } catch (std::exception &e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}

net::awaitable<void> transfer(tcp::socket &from, tcp::socket &to) {
    Buffer data = {};
    for (;;) {
        const auto [error, length] = co_await from.async_read_some(net::buffer(data),
                                                                   net::as_tuple(net::use_awaitable));
        if (error == net::error::eof) {
            break;
        }
        co_await net::async_write(to, net::buffer(data, length), net::use_awaitable);
    }
}

State onGreeting(Buffer &data, std::size_t &length) {
    if (data[0] != SOCKS_VER) {
        return State::EndOfSession;
    }
    data[0] = SOCKS_VER;
    data[1] = AuthMethod::NoAuthRequired;
    length = 2;
    return State::Request;
}

net::awaitable<std::tuple<State, std::unique_ptr<tcp::socket>>> onRequest(const tcp::socket::executor_type &executor,
                                                                          const tcp::endpoint &serverEndpoint,
                                                                          Buffer &data,
                                                                          std::size_t &length) {
    if (data[0] != SOCKS_VER) {
        co_return std::make_tuple(State::EndOfSession, nullptr);
    }

    constexpr std::size_t REPLY_LENGTH = 10;
    std::optional<tcp::endpoint> targetEndpoint;
    auto replyCode = ReplyCode::Succeeded;

    const auto addressType = data[3];
    if (addressType == AddressType::IpV4) {
        net::ip::port_type targetPort = 0;
        std::memcpy(&targetPort, &data[8], sizeof(targetPort));
        targetEndpoint = tcp::endpoint(net::ip::address_v4({data[4],
                                                            data[5],
                                                            data[6],
                                                            data[7]}), ntohs(targetPort));
    } else if (addressType == AddressType::DomainName) {
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
            std::cerr << hostName << "-" << error.message() << std::endl;
            replyCode = ReplyCode::HostUnreachable;
        } else if (!endpoints.empty()) {
            targetEndpoint = *endpoints.begin();
        }
    } else {
        replyCode = ReplyCode::AddressTypeNotSupported;
    }

    std::unique_ptr<tcp::socket> targetSocket = nullptr;

    if (targetEndpoint) {
        const auto cmdType = data[1];
        if (cmdType == CmdType::Connect) {
            targetSocket = std::make_unique<tcp::socket>(executor);
            const auto [error] = co_await targetSocket->async_connect(*targetEndpoint,
                                                                      net::as_tuple(net::use_awaitable));
            if (error) {
                switch (error.value()) {
                    case net::error::network_unreachable:
                        replyCode = ReplyCode::NetworkUnreachable;
                        break;
                    case net::error::connection_refused:
                        replyCode = ReplyCode::ConnectionRefused;
                        break;
                    default:
                        break;
                }
                std::cerr << *targetEndpoint << "-" << error.message() << std::endl;
            }
        } else {
            replyCode = ReplyCode::CommandNotSupported;
        }
    } else {
        co_return std::make_tuple(State::EndOfSession, nullptr);
    }

    data[0] = SOCKS_VER;
    data[1] = replyCode;
    data[2] = RESERVED_FIELD;
    data[3] = AddressType::IpV4;

    const auto addrBytes = serverEndpoint.address().to_v4().to_bytes();
    static_assert(std::size(addrBytes) == 4);
    std::copy(std::begin(addrBytes), std::end(addrBytes), &data[4]);

    const auto serverPort = htons(serverEndpoint.port());
    static_assert(sizeof(serverPort) == 2);
    std::memcpy(&data[8], &serverPort, sizeof(serverPort));

    length = REPLY_LENGTH;
    co_return std::make_tuple(State::Transfer, std::move(targetSocket));
}

net::awaitable<State>
onTransfer(tcp::socket &client, tcp::socket &targetSocket, const Buffer &data, const size_t length) {
    using namespace net::experimental::awaitable_operators;

    co_await net::async_write(targetSocket, net::buffer(data, length), net::use_awaitable);
    co_await (transfer(client, targetSocket) && transfer(targetSocket, client));
    co_return State::EndOfSession;
}

net::awaitable<void> startSession(tcp::socket client) {
    State state = State::Greeting;
    Buffer data = {};
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
                    state = onGreeting(data, length);
                    break;
                case State::Request:
                    std::tie(state, targetSocket)
                            = co_await onRequest(client.get_executor(), client.local_endpoint(), data, length);
                    break;
                case State::Transfer:
                    state = targetSocket ? co_await onTransfer(client, *targetSocket, data, length)
                                         : State::EndOfSession;
                    break;
                default:
                    break;
            }

            if (state != State::EndOfSession) {
                co_await net::async_write(client, net::buffer(data, length), net::use_awaitable);
            } else {
                break;
            }
        }
    } catch (const std::exception &e) {
        std::cerr << "Proxy error: " << e.what() << "\n";
    }
}

net::awaitable<void> listen(tcp::acceptor &acceptor) {
    using namespace std::chrono_literals;

    for (;;) {
        auto [error, client] = co_await acceptor.async_accept(net::as_tuple(net::use_awaitable));
        if (!error) {
            const auto executor = client.get_executor();
            net::co_spawn(executor, startSession(std::move(client)), net::detached);
        } else {
            std::cerr << "Accept failed: " << error.message() << "\n";
            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(100ms);
            co_await timer.async_wait(net::use_awaitable);
        }
    }
}
