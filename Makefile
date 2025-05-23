ifeq ($(findstring MINGW64,$(shell uname -s)),MINGW64)
  # cgo accepts not '/c/path' but 'c:/path'
  PWD=$(shell pwd|sed s'@^/\([a-z]\)/@\1:/@')
else
  PWD=$(shell pwd)
endif
MCL_DIR?=$(PWD)/mcl
include $(MCL_DIR)/common.mk
LIB_DIR=lib
OBJ_DIR=obj
EXE_DIR=bin
CFLAGS += -std=c++11
LDFLAGS += -lpthread

MCL_FP_BIT?=384
MCL_FR_BIT?=256
ifeq ($(MCL_FP_BIT)_$(MCL_FR_BIT),256_256)
  MCL_SUF=256
endif
ifeq ($(MCL_FP_BIT)_$(MCL_FR_BIT),384_256)
  MCL_SUF=384_256
endif
ifeq ($(MCL_FP_BIT)_$(MCL_FR_BIT),384_384)
  MCL_SUF=384
endif

#CFLAGS+=-DMCL_FP_BIT=$(MCL_FP_BIT)
#CFLAGS+=-DMCL_FR_BIT=$(MCL_FR_BIT)

MCL_SNAME=mcl
ifeq ($(MCL_SUF),256)
SRC_SRC=bls_c256.cpp
TEST_SRC=bls256_test.cpp bls_c256_test.cpp
endif
ifeq ($(MCL_SUF),384_256)
SRC_SRC=bls_c384_256.cpp
TEST_SRC=bls384_256_test.cpp bls_c384_256_test.cpp
SAMPLE_SRC=bls_smpl.cpp bls12_381_smpl.cpp
endif
ifeq ($(MCL_SUF),384)
SRC_SRC=bls_c384.cpp
TEST_SRC=bls384_test.cpp bls_c384_test.cpp
endif

CFLAGS+=-I$(MCL_DIR)/include
ifeq ($(BLS_ETH),1)
  CFLAGS+=-DBLS_ETH
endif

BLS_LIB=$(LIB_DIR)/libbls$(MCL_SUF).a
BL_SNAME=bls$(MCL_SUF)
BLS_SLIB=$(LIB_DIR)/lib$(BLS_SNAME).$(LIB_SUF)
all: $(BLS_LIB) $(BLS_SLIB)

MCL_LIB=$(MCL_DIR)/lib/lib$(MCL_SNAME).a

$(MCL_LIB):
	$(MAKE) -C $(MCL_DIR) lib/lib$(MCL_SNAME).a MCL_FP_BIT=$(MCL_FP_BIT) MCL_FR_BIT=$(MCL_FR_BIT)

$(BLS_LIB): $(OBJ_DIR)/bls_c$(MCL_SUF).o
	$(AR) $(ARFLAGS) $@ $<

ifneq ($(findstring $(OS),mac/mingw64),)
  COMMON_LIB=$(GMP_LIB) $(OPENSSL_LIB) -lstdc++
  BLS_SLIB_LDFLAGS+=$(COMMON_LIB)
endif
ifeq ($(OS),mingw64)
  CFLAGS+=-I$(MCL_DIR)
  BLS_SLIB_LDFLAGS+=-Wl,--out-implib,$(LIB_DIR)/lib$(BLS_SNAME).a
endif
$(BLS_SLIB): $(OBJ_DIR)/bls_c$(MCL_SUF).o $(MCL_LIB)
	$(PRE)$(CXX) -shared -o $@ $< -L$(MCL_DIR)/lib -l$(MCL_SNAME) $(LDFLAGS) $(BLS_SLIB_LDFLAGS)

VPATH=test sample src

.SUFFIXES: .cpp .d .exe

$(OBJ_DIR)/%.o: %.cpp
	$(PRE)$(CXX) $(CFLAGS) -c $< -o $@ -MMD -MP -MF $(@:.o=.d)

$(EXE_DIR)/%$(MCL_SUF)_test.exe: $(OBJ_DIR)/%$(MCL_SUF)_test.o $(BLS_LIB) $(MCL_LIB)
	$(PRE)$(CXX) $< -o $@ $(BLS_LIB) -L$(MCL_DIR)/lib -l$(MCL_SNAME) $(LDFLAGS)

# sample exe links libbls384_256.a
$(EXE_DIR)/%.exe: $(OBJ_DIR)/%.o $(BLS_LIB) $(MCL_LIB)
	$(PRE)$(CXX) $< -o $@ $(BLS_LIB) -L$(MCL_DIR)/lib -l$(MCL_SNAME) $(LDFLAGS)
ifeq ($(OS),mac)
	install_name_tool bin/bls_smpl.exe -change lib/lib$(MCL_SNAME).dylib $(MCL_DIR)/lib/lib$(MCL_SNAME).dylib
endif

SAMPLE_EXE=$(addprefix $(EXE_DIR)/,$(SAMPLE_SRC:.cpp=.exe))
sample: $(SAMPLE_EXE)

TEST_EXE=$(addprefix $(EXE_DIR)/,$(TEST_SRC:.cpp=.exe))
ifeq ($(OS),mac)
  LIBPATH_KEY=DYLD_LIBRARY_PATH
else
  LIBPATH_KEY=LD_LIBRARY_PATH
endif
test_ci: $(TEST_EXE)
#	@sh -ec 'for i in $(TEST_EXE); do echo $$i; env PATH=$$PATH:$(MCL_DIR)/lib $(LIBPATH_KEY)=$(MCL_DIR)/lib LSAN_OPTIONS=verbosity=1 log_threads=1 $$i; done'
	@sh -ec 'for i in $(TEST_EXE); do echo $$i; env PATH=$$PATH:$(MCL_DIR)/lib $(LIBPATH_KEY)=$(MCL_DIR)/lib $$i; done'
ifeq ($(MCL_SUF),384_256)
	$(MAKE) sample_test
endif

test: $(TEST_EXE)
	@echo test $(TEST_EXE)
	@sh -ec 'for i in $(TEST_EXE); do env PATH=$$PATH:$(MCL_DIR)/lib $(LIBPATH_KEY)=$(MCL_DIR)/lib $$i|grep "ctest:name"; done' > result.txt
	@grep -v "ng=0, exception=0" result.txt; if [ $$? -eq 1 ]; then echo "all unit tests succeed"; else exit 1; fi
ifeq ($(MCL_SUF),384_256)
	$(MAKE) sample_test
endif

sample_test: $(EXE_DIR)/bls_smpl.exe
	env PATH=$$PATH:$(MCL_DIR)/lib $(LIBPATH_KEY)=$(MCL_DIR)/lib python3 bls_smpl.py

# PATH is for mingw, LD_LIBRARY_PATH is for linux, DYLD_LIBRARY_PATH is for mac
COMMON_LIB_PATH="../../../lib:../../../$(MCL_DIR)/lib"
PATH_VAL=$$PATH:$(COMMON_LIB_PATH) LD_LIBRARY_PATH=$(COMMON_LIB_PATH) DYLD_LIBRARY_PATH=$(COMMON_LIB_PATH) CGO_LDFLAGS="-L../../../lib -L$(OPENSSL_DIR)/lib" CGO_CFLAGS="-I$(PWD)/include -I$(MCL_DIR)/include"
test_go: ffi/go/bls/bls.go ffi/go/bls/bls_test.go $(BLS_LIB) $(MCL_LIB)
	$(RM) $(BLS_SLIB)
	cd ffi/go/bls && go test

test_eth: bin/bls_c384_256_test.exe
	bin/bls_c384_256_test.exe

EMCC_OPT=-I./include -I./src -I$(MCL_DIR)/include -I./ -Wall -Wextra
EMCC_OPT+=-O3 -DNDEBUG
EMCC_OPT+=-s WASM=1 -s NO_EXIT_RUNTIME=1 -s NODEJS_CATCH_EXIT=0 -s NODEJS_CATCH_REJECTION=0 #-s ASSERTIONS=1
EMCC_OPT+=-s MODULARIZE=1
EMCC_OPT+=-s EXPORT_NAME='blsCreateModule'
EMCC_OPT+=-s STRICT_JS=1
EMCC_OPT+=-s SINGLE_FILE=1
EMCC_OPT+=-s MINIFY_HTML=0
EMCC_OPT+=--minify 0
EMCC_OPT+=-DCYBOZU_MINIMUM_EXCEPTION
EMCC_OPT+=-s ABORTING_MALLOC=0
JS_DEP=src/bls_c384.cpp $(MCL_DIR)/src/fp.cpp Makefile

../bls-wasm/bls_c.js: $(JS_DEP)
	emcc -o $@ src/bls_c384.cpp $(MCL_DIR)/src/fp.cpp $(EMCC_OPT) -DMCL_MAX_BIT_SIZE=384 -DMCL_USE_WEB_CRYPTO_API -s DISABLE_EXCEPTION_CATCHING=1 -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING -DMCL_DONT_USE_CSPRNG -fno-exceptions -MD -MP -MF obj/bls_c384.d

bls-wasm:
	$(MAKE) ../bls-wasm/bls_c.js

../bls-eth-wasm/bls_c.js: src/bls_c384_256.cpp $(MCL_DIR)/src/fp.cpp Makefile
	emcc -o $@ src/bls_c384_256.cpp $(MCL_DIR)/src/fp.cpp $(EMCC_OPT) -DMCL_MAX_BIT_SIZE=384 -DBLS_ETH -DMCL_USE_WEB_CRYPTO_API -s DISABLE_EXCEPTION_CATCHING=1 -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING -DMCL_DONT_USE_CSPRNG -fno-exceptions -MD -MP -MF obj/bls_c384_256.d
bls-eth-wasm:
	$(MAKE) ../bls-eth-wasm/bls_c.js

#CLANG_WASM_OPT= -fno-builtin  --target=wasm32-unknown-unknown-wasm -Wno-unused-parameter -ffreestanding -fno-exceptions -fvisibility=hidden -Wall -Wextra -fno-threadsafe-statics -nodefaultlibs -nostdlib -fno-use-cxa-atexit -fno-unwind-tables -fno-rtti -nostdinc++ -DLLONG_MIN=-0x8000000000000000LL

BASE_CFLAGS=-O3 -g -DNDEBUG -I ./include -I $(MCL_DIR)/include -I ./src -fPIC -DMCL_MAX_BIT_SIZE=384 -DMCL_SIZEOF_UNIT=8 -DMCL_LLVM_BMI2=0 -DCYBOZU_DONT_USE_EXCEPTION -DMCL_DONT_USE_CSPRNG -DCYBOZU_DONT_USE_STRING -DCYBOZU_MINIMUM_EXCEPTION -Wno-unused-parameter -Wall -Wextra -fno-threadsafe-statics -fno-use-cxa-atexit -fno-unwind-tables -fno-builtin -fvisibility=hidden -fno-rtti -fno-stack-protector -fno-exceptions -nostdinc++
WASM_OUT_DIR=../bls-wasm/
WASM_SRC_BASENAME=bls_c384
ifeq ($(BLS_ETH),1)
  BASE_CFLAGS+=-DBLS_ETH
  WASM_OUT_DIR=../bls-eth-wasm/
  WASM_SRC_BASENAME=bls_c384_256
endif
CLANG_WASM_OPT=$(BASE_CFLAGS) --target=wasm32-unknown-unknown-wasm -ffreestanding -nostdlib -I /usr/include -DMCL_USE_LLVM=1
# apt install liblld-10-dev
bls-wasm-by-clang: $(MCL_DIR)/src/base64m.ll
	$(CXX) -x c -c -o $(OBJ_DIR)/mylib.o src/mylib.c $(CLANG_WASM_OPT) -Wstrict-prototypes
	$(CXX) -c -o $(OBJ_DIR)/base64m.o $(MCL_DIR)/src/base64m.ll $(CLANG_WASM_OPT) -std=c++03
	$(CXX) -c -o $(OBJ_DIR)/$(WASM_SRC_BASENAME).o src/$(WASM_SRC_BASENAME).cpp $(CLANG_WASM_OPT) -std=c++03
	$(CXX) -c -o $(OBJ_DIR)/fp.o $(MCL_DIR)/src/fp.cpp $(CLANG_WASM_OPT) -std=c++03
	wasm-ld-10 --no-entry --export-dynamic -o $(WASM_OUT_DIR)/bls.wasm $(OBJ_DIR)/$(WASM_SRC_BASENAME).o $(OBJ_DIR)/fp.o $(OBJ_DIR)/mylib.o $(OBJ_DIR)/base64m.o #-z stack-size=524288

bin/minsample: sample/minsample.c
	$(CXX) -o bin/minsample sample/minsample.c src/mylib.c src/$(WASM_SRC_BASENAME).cpp $(MCL_DIR)/src/fp.cpp $(BASE_CFLAGS) -std=c++03 -DMCL_DONT_USE_XBYAK -DMCL_USE_VINT -DMCL_VINT_FIXED_BUFFER -DMCL_DONT_USE_OPENSSL

$(MCL_DIR)/src/base64.ll:
	$(MAKE) -C $(MCL_DIR) src/base64.ll

$(MCL_DIR)/src/base64m.ll:
	$(MAKE) -C $(MCL_DIR) src/base64m.ll

# This library is slow because of no x64-optimized code. This is for checking a standalone environment.
# Use make -f Makefile.onelib to get a static library including libmcl.a
MIN_CFLAGS=-std=c++03 -O3 -DNDEBUG -fPIC -DMCL_DONT_USE_OPENSSL -DMCL_SIZEOF_UNIT=8 -DMCL_MAX_BIT_SIZE=384 -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING -I./include -I $(MCL_DIR)/include
ifneq ($(MIN_WITH_XBYAK),1)
  MIN_CFLAGS+=-DMCL_DONT_USE_XBYAK -fno-exceptions -fno-rtti -fno-threadsafe-statics -nodefaultlibs -nostdlib -fno-use-cxa-atexit -fno-unwind-tables -nostdinc++
endif
ifeq ($(BLS_ETH),1)
  MIN_CFLAGS+=-DBLS_ETH
endif
minimized_static:
	$(CXX) -c -o $(OBJ_DIR)/fp.o $(MCL_DIR)/src/fp.cpp $(MIN_CFLAGS)
	$(CXX) -c -o $(OBJ_DIR)/bls_c384_256.o src/bls_c384_256.cpp $(MIN_CFLAGS)
ifeq ($(CPU),x86-64)
	$(CXX) -c -o $(OBJ_DIR)/bint-asm.o $(MCL_DIR)/src/asm/bint-x64-amd64.S
else
	clang++$(LLVM_VER) -c -o $(OBJ_DIR)/bint-asm.o $(MCL_DIR)/$(BINT_SRC)
endif
	$(AR) $(ARFLAGS) $(LIB_DIR)/libbls384_256.a $(OBJ_DIR)/bls_c384_256.o $(OBJ_DIR)/fp.o $(OBJ_DIR)/bint-asm.o

$(EXE_DIR)/minimized_static_test.exe: minimized_static
	$(CXX) -o $@ test/bls_c384_256_test.cpp $(LIB_DIR)/libbls384_256.a -DMCL_MAX_BIT_SIZE=384 -I ./include -I $(MCL_DIR)/include -DNDEBUG

minimized_static_test: $(EXE_DIR)/minimized_static_test.exe
	$(EXE_DIR)/minimized_static_test.exe


clean:
	make -C $(MCL_DIR) clean
	$(RM) $(OBJ_DIR)/*.d $(OBJ_DIR)/*.o $(EXE_DIR)/*.exe $(LIB_DIR)/*.a $(LIB_DIR)/*.$(LIB_SUF) $(LIB_DIR)/*. $(GEN_EXE) $(ASM_SRC) $(ASM_OBJ) $(LLVM_SRC)

ALL_SRC=$(SRC_SRC) $(TEST_SRC) $(SAMPLE_SRC)
DEPEND_FILE=$(addprefix $(OBJ_DIR)/, $(ALL_SRC:.cpp=.d))
-include $(DEPEND_FILE)

PREFIX?=/usr/local
prefix?=$(PREFIX)
includedir?=$(prefix)/include
libdir?=$(prefix)/lib
INSTALL?=install
INSTALL_DATA?=$(INSTALL) -m 644
install: lib/libbls256.a lib/libbls256.$(LIB_SUF) lib/libbls384.a lib/libbls384.$(LIB_SUF) lib/libbls384_256.a lib/libbls384_256.$(LIB_SUF)
	$(MKDIR) $(DESTDIR)$(includedir)/bls $(DESTDIR)$(libdir)
	$(INSTALL_DATA) include/bls/*.h* $(DESTDIR)$(includedir)/bls
	$(INSTALL_DATA) lib/libbls*.a $(DESTDIR)$(libdir)
	$(INSTALL) -m 755 lib/libbls*.$(LIB_SUF) $(DESTDIR)$(libdir)

.PHONY: test bls-wasm ios

# don't remove these files automatically
.SECONDARY: $(addprefix $(OBJ_DIR)/, $(ALL_SRC:.cpp=.o))

