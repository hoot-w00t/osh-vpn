# osh-vpn
[![Build project](https://github.com/hoot-w00t/osh-vpn/actions/workflows/build.yml/badge.svg)](https://github.com/hoot-w00t/osh-vpn/actions/workflows/build.yml) [![GitHub license](https://img.shields.io/github/license/hoot-w00t/osh-vpn)](https://github.com/hoot-w00t/osh-vpn/blob/main/LICENSE)

Osh is an experimental mesh VPN made as a fun and learning project.

Although it has basic authentication and encryption it was not tested much and I'm no expert in those fields, so if you are looking for a reliable and safe VPN, don't use Osh.

## Building the project
### Dependencies
[OpenSSL](https://www.openssl.org/) is used for cryptography and [easyconf](https://github.com/hoot-w00t/easyconf/) to handle configuration files.

[easyconf](https://github.com/hoot-w00t/easyconf/) is a submodule of this repository and will be built automatically when building Osh.

#### Debian/Ubuntu
```
sudo apt install make git gcc pkg-config libssl-dev cmake
```

#### Arch Linux
```
sudo pacman -S --needed make git gcc pkgconf openssl cmake
```

#### Cygwin
```
make git gcc-core pkgconf libssl-devel cmake
```

### Compiling
Clone the repository and navigate to it, then run
```
git submodule update --init
mkdir build && cd build
cmake ..
make
```

### Build types
You can use different build types with `-DCMAKE_BUILD_TYPE=<build_type>` when running CMake
| Build type     | Description                                                                                  |
|----------------|----------------------------------------------------------------------------------------------|
| Debug          | Disables compiler optimizations and enables more debug information (default)                 |
| Release        | Enables compiler optimizations (level 2)                                                     |
| MinSizeRel     | Enables compiler optimizations for smaller file sizes                                        |
| RelWithDebInfo | Same as Release but also enables default debug information                                   |
| NativeRelease  | Same as Release with optimizations specific to the host CPU                                  |
| Hardened       | Same as RelWithDebInfo but also enables stack protection (https://wiki.debian.org/Hardening) |

### Unit tests
You can also build unit tests by configuring CMake with `-DENABLE_UNIT_TESTS=ON`.
They are built using [Criterion](https://github.com/Snaipe/Criterion), which you'll have to install in order to compile and execute the tests.
```
cmake .. -DENABLE_UNIT_TESTS=ON
make
ctest
```
It's also possible to run the unit tests alone with `./oshd_tests`.

## Installing
It is possible to install Osh with `sudo make install` after compiling.

You can change the installation prefix to install files to another location by configuring the project with `-DCMAKE_INSTALL_PREFIX=<path>` (defaults to `/usr/local` on Unix and `C:\Program Files` on Windows).

After installing you should find an `install_manifest.txt` in your build directory, which contains a list of all the files that were installed to your system.