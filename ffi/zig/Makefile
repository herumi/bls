all: sample

lib:
	make -C ../../ -f Makefile.onelib ETH_CFLAGS=-DBLS_ETH LIB_DIR=lib

sample: lib
	zig build

fmt:
	zig fmt *.zig

clean:
	\rm -rf .zig-cache/  zig-out/
