#ifndef BOOST_ASIO_SOCKS5_COMMON_H
#define BOOST_ASIO_SOCKS5_COMMON_H

#include <boost/asio.hpp>

namespace net = boost::asio;

namespace socks5 {
    inline constexpr std::uint8_t VERSION = 5;
    inline constexpr std::uint8_t RESERVED_FIELD = 0;
    inline constexpr std::uint8_t AUTH_METHOD_VERSION = 1;
    inline constexpr std::size_t REPLY_LENGTH_FOR_REQUEST = 10;

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

    enum AuthMethod : std::uint8_t {
        NoAuthRequired = 0,
        GSSAPI = 1,
        UsernamePassword = 2
    };

    enum AuthStatusReply : std::uint8_t {
        Successful = 0,
        Failure = 1
    };

    enum ReplyCode : std::uint8_t {
        Succeeded = 0,
        NetworkUnreachable = 3,
        HostUnreachable = 4,
        ConnectionRefused = 5,
        CommandNotSupported = 7,
        AddressTypeNotSupported = 8
    };

}  // namespace socks5

template<typename ReadableSocketType, typename WritableSocketType>
net::awaitable<std::size_t> transfer(ReadableSocketType &readableSocket,
                                     WritableSocketType &writableSocket,
                                     const std::size_t maxReadSize = 0) {
    std::vector<std::uint8_t> data(4 * 1024);
    std::size_t readBytes = 0;
    for (;;) {
        const auto [readError, readLength] = co_await readableSocket.async_read_some(net::buffer(data),
                                                                                     net::as_tuple(net::use_awaitable));
        readBytes += readLength;
        if (readError == net::error::eof || readError == boost::system::errc::operation_canceled) {
            break;
        }
        const auto [writeError, writeLength] = co_await net::async_write(writableSocket,
                                                                         net::buffer(data, readLength),
                                                                         net::as_tuple(net::use_awaitable));
        if (writeError == net::error::eof || writeError == boost::system::errc::operation_canceled) {
            break;
        }
        if (maxReadSize > 0 && readBytes >= maxReadSize) {
            break;
        }
    }
    co_return readBytes;
}

#endif //BOOST_ASIO_SOCKS5_COMMON_H
