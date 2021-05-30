# osh-vpn
[![GitHub license](https://img.shields.io/github/license/hoot-w00t/osh-vpn)](https://github.com/hoot-w00t/osh-vpn/blob/main/LICENSE)

Osh is an experimental mesh VPN made as a fun and learning project.

Although it has basic authentication and encryption it was not tested much and I'm no expert in those fields, so if you are looking for a reliable and safe VPN, don't use Osh.

## Building
It uses the [OpenSSL library](https://www.openssl.org/) for all cryptography work.

Clone the repository and navigate to it, then just run
```
make
```

You can also build and run unit tests with
```
make test
```
These unit tests require [Criterion](https://github.com/Snaipe/Criterion).