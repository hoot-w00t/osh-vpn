# osh-vpn
[![Build status](https://github.com/hoot-w00t/osh-vpn/actions/workflows/build.yml/badge.svg)](https://github.com/hoot-w00t/osh-vpn/actions/workflows/build.yml) [![GitHub license](https://img.shields.io/github/license/hoot-w00t/osh-vpn)](https://github.com/hoot-w00t/osh-vpn/blob/main/LICENSE)

Osh is an experimental mesh VPN made as a fun and learning project.

## Building the project
### Dependencies
- [OpenSSL](https://www.openssl.org/)
- [easyconf](https://github.com/hoot-w00t/easyconf/) (which is a submodule of this repository and compiled automatically)
- [Criterion](https://github.com/Snaipe/Criterion) (**optional**, only needed if unit tests are enabled)

#### Debian/Ubuntu
```
apt install make git gcc pkg-config libssl-dev cmake
```

#### Arch Linux
```
pacman -S --needed make git gcc pkgconf openssl cmake
```

#### Mingw64 (with MSYS2)
```
pacman -S --needed base-devel git mingw-w64-x86_64-toolchain mingw-w64-x86_64-toolchain-libwinpthread mingw-w64-x86_64-pkgconf mingw-w64-x86_64-make mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl
```

### Compiling
Clone the repository and navigate to it, then run
```
git submodule update --init
cmake -B build
cmake --build build
```
The binary will be located inside the `build` directory.

The `cmake -B build` command can be invoked again to change build parameters.
Build options can be set by adding `-D<option>=<value>` to the `cmake` command.

### Build types
Build types can be changed with `-DCMAKE_BUILD_TYPE=<build_type>`
| Build type     | Description                                                                                  |
|----------------|----------------------------------------------------------------------------------------------|
| Debug          | Disables compiler optimizations and enables more debug information (default)                 |
| Release        | Enables compiler optimizations (level 2)                                                     |
| MinSizeRel     | Enables compiler optimizations for smaller file sizes                                        |
| RelWithDebInfo | Same as Release but also enables default debug information                                   |
| NativeRelease  | Same as Release with optimizations specific to the host CPU                                  |

### Other build options
| Option              | Default value | Description |
|---------------------|---------------|-------------|
| `ENABLE_UNIT_TESTS` | `OFF`         | Build unit tests, they can be run with `ctest --output-on-failure` or directly with `./oshd_tests`. |
| `AIO_BACKEND`       | `auto`        | Choose the backend used for polling I/O events. `auto` automatically chooses the best available from the following backends: `epoll`, `poll`, `windows`. |
| `ENABLE_SYSTEMD`    | `OFF`         | Configure systemd service files |
| `DISABLE_EVENTS_TIMERFD` | `OFF`    | Disable the use of `timerfd` for timed events even when it is available |
| `ENABLE_HARDENING`  | `ON`          | Enable hardening flags for release builds ([https://wiki.debian.org/Hardening](https://wiki.debian.org/Hardening)) |
| `TUNTAP_DISABLE_EMULATION` | `OFF`  | Disable TUN/TAP emulation layers |

## Installing
It is possible to install Osh with `cmake --install <builddir>` after compiling.

The installation prefix can be changed to install files to another location by setting `-DCMAKE_INSTALL_PREFIX=<path>` (defaults to `/usr/local` on Unix and `C:\Program Files` on Windows).

After installing there will be an `install_manifest.txt` in your build directory, which lists all the files that were installed.
