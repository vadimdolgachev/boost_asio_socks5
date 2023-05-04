## boost_asio_socks5

## Build
```bash
cmake -DCMAKE_TOOLCHAIN_FILE=${VCPKG_HOME}/scripts/buildsystems/vcpkg.cmake -S. -B./build -G Ninja && cmake --build ./build
```

## Usage
`curl --socks5 127.0.0.1:10800 http://ident.me`

`curl --socks5-hostname 127.0.0.1:10800 https://ident.me`

`curl --socks5 user:pass@127.0.0.1:10800 http://ident.me`

## Rfc
https://www.rfc-editor.org/rfc/rfc1928

https://www.rfc-editor.org/rfc/rfc1929

https://www.rfc-editor.org/rfc/rfc1961