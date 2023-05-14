## boost_asio_socks5

## Build
```bash
cmake -DCMAKE_TOOLCHAIN_FILE=${VCPKG_HOME}/scripts/buildsystems/vcpkg.cmake -S. -B./build -G Ninja && cmake --build ./build
```

## Usage
```bash 
curl --socks5 127.0.0.1:10800 http://ident.me
```

```bash 
curl --socks5-hostname 127.0.0.1:10800 https://ident.me
```

```bash 
curl --socks5 user:pass@127.0.0.1:10800 http://ident.me
```

## Creating ssl keys
```bash
openssl req -x509 -newkey rsa:4096 -keyout private_key.pem -out cert.pem \
        -sha256 -days 365 -nodes \
        -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
openssl dhparam -dsaparam -out dh_key.pem 4096
```

## Rfc
https://www.rfc-editor.org/rfc/rfc1928

https://www.rfc-editor.org/rfc/rfc1929

https://www.rfc-editor.org/rfc/rfc1961