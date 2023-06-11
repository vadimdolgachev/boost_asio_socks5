#ifndef BOOST_ASIO_SOCKS5_COMMON_H
#define BOOST_ASIO_SOCKS5_COMMON_H

namespace socks5 {
    inline constexpr std::uint8_t VERSION = 5;
    inline constexpr std::uint8_t RESERVED_FIELD = 0;
    inline constexpr std::uint8_t AUTH_METHOD_VERSION = 1;

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

#endif //BOOST_ASIO_SOCKS5_COMMON_H
