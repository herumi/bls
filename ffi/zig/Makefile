all: sample

lib:
	make -C ../../ -f Makefile.onelib ETH_CFLAGS=-DBLS_ETH LIB_DIR=lib

sample: lib
	zig build

run: sample
	zig-out/bin/sample

fmt:
	zig fmt *.zig

test:
	zig build test

clean:
	\rm -rf .zig-cache/  zig-out/
