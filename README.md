# osh-vpn
[![Build project](https://github.com/hoot-w00t/osh-vpn/actions/workflows/build.yml/badge.svg)](https://github.com/hoot-w00t/osh-vpn/actions/workflows/build.yml) [![GitHub license](https://img.shields.io/github/license/hoot-w00t/osh-vpn)](https://github.com/hoot-w00t/osh-vpn/blob/main/LICENSE)

Osh is an experimental mesh VPN made as a fun and learning project.

Although it has basic authentication and encryption it was not tested much and I'm no expert in those fields, so if you are looking for a reliable and safe VPN, don't use Osh.

## Building
It uses the [OpenSSL library](https://www.openssl.org/) for all cryptography work.

Install the dependencies
```
# On Debian/Ubuntu
sudo apt install make git gcc pkg-config libssl-dev
```
```
# On Arch Linux
sudo pacman -S --needed make git gcc pkgconf openssl
```


Clone the repository and navigate to it, then run
```
make
```

You can also build and run unit tests with
```
make test
```
These unit tests require [Criterion](https://github.com/Snaipe/Criterion).

## Installation
It is possible to install or uninstall the built binary with
```
sudo make install
sudo make uninstall
```

You can specify a custom prefix if you would like to install/uninstall it to/from a different location (don't put a slash at the end of the prefix)
```
sudo make install INSTALL_PREFIX=/usr
```