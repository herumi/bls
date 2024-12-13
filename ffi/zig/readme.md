# How to build libbls384_256.a and Zig sample

```
git clone --recursive https://github.com/herumi/bls
cd bls
make -f Makefile.onelib ETH_CFLAGS=-DBLS_ETH LIB_DIR=lib
cd ffi/zig
zig build
zig-out/bin/sample
```
