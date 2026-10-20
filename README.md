# backbone-bitnames

Drop-in replacement client for **BitNames on eCash (slot 2)**: consensus-, P2P-, mainchain-
and RPC-compatible with the octobocto fork of plain-bitnames v0.18.x (0.18.0-0.18.2 share the
rules), which is what betanet runs. C++20 on the shared engine `backbone-core`.

* `doc/bitnames.md`: status, drop-in surface, reproduced quirks, kept fixes, remaining work.
* `doc/differential-tests.md`: what to run against their binaries on the test machine.
* `core/doc/DESIGN.md`: the engine (codecs, crypto, store, QUIC, gRPC, archive/P2P templates).

Inspired by BitNames by LayerTwo Labs.

## Layout

```
core/               git submodule ../backbone-core (engine, test harness, depends/, cmake/)
chains/bitnames/    libbitnames_core (types, merkle, state machine, JSON, betanet fixture)
                    libbitnames_node (node, wallet, app/RPC); binaries bitnames, bitnames-cli,
                    bitnames-fetch-blocks
tests/              BitNames known-answer and quirk tests (tests/data/betanet = public data);
                    the test binary also runs the core's own cases
```

Clone with `git clone --recurse-submodules`, or `git submodule update --init` afterwards.

## Build (Linux)

```
core/depends/fetch.sh
cmake -S core/depends -B core/depends/work/linux       # OpenSSL 3.5.9 + ngtcp2 1.25.0
~/skydoge/tools/build.sh ~/skydoge/backbone-bitnames core/depends/work/linux
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo   # system libsodium, sqlite3, nghttp2
~/skydoge/tools/build.sh ~/skydoge/backbone-bitnames build
build/tests/bt_tests
```

## Cross-build (Windows, mingw-w64 posix)

```
cmake -S core/depends -B core/depends/work/mingw64 -DBT_HOST=mingw64 -DCMAKE_TOOLCHAIN_FILE=$PWD/core/cmake/mingw64.cmake
~/skydoge/tools/build.sh ~/skydoge/backbone-bitnames core/depends/work/mingw64
PKG_CONFIG_LIBDIR=$PWD/core/depends/built/mingw64/lib/pkgconfig cmake -S . -B build-mingw64 \
  -DCMAKE_TOOLCHAIN_FILE=$PWD/core/cmake/mingw64.cmake -DBT_DEPENDS_PREFIX=$PWD/core/depends/built/mingw64 \
  -DBT_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release
~/skydoge/tools/build.sh ~/skydoge/backbone-bitnames build-mingw64
```

## Run on betanet

```
bitnames --headless --mainchain-grpc-host 127.0.0.1 --mainchain-grpc-port 50051
bitnames --headless --bt-mainchain-grpc-url https://enforcer.beta.ecash.ninja   # public enforcer (TLS)
bitnames-cli get-blockcount           # default --rpc-url http://127.0.0.1:6002
```
