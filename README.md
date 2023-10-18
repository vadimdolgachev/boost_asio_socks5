## boost_asio_socks5

```
+------------------+
| socks5 client    |
+------------------+
                       *
                         *
                           *
                             +-------------------+       +---------------+
                             | socks5 ssl tunnel | * * * | socks5 server |
                             +-------------------+       +---------------+
                           *
                         *
                       *
+------------------+
| http proxy       |
+------------------+

```

## Build
```bash
cmake -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake -S. -B./build -G Ninja && cmake --build ./build
```

## Usage
### As socks5 proxy:

```bash
curl --socks5 127.0.0.1:10800 http://ident.me
```

```bash
curl --socks5-hostname 127.0.0.1:10800 https://ident.me
```

```bash
curl --socks5 user:pass@127.0.0.1:10800 http://ident.me
```

### As http proxy:
```bash
curl -x 127.0.0.1:10802 https://ident.me
```

## Creating ssl keys
```bash
openssl req -x509 -newkey rsa:4096 -keyout private_key.pem -out cert.pem \
        -sha256 -days 365 -nodes \
        -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
openssl dhparam -dsaparam -out dh_key.pem 4096
```

## systemd

1. copy .service files to $HOME/.config/systemd/user/

2. set the necessary environment variables in .service file

## Client side
```bash
systemctl --user daemon-reload
systemctl --user start socks5_ssl_tunnel.service
```

## Server side
```bash
systemctl --user daemon-reload
systemctl --user start socks5_server.service
```

## Rfc
https://www.ietf.org/rfc/rfc1928

https://www.ietf.org/rfc/rfc1929

https://www.ietf.org/rfc/rfc1961

https://www.ietf.org/rfc/rfc2817