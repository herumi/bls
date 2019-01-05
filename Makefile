ifeq ($(findstring MINGW64,$(shell uname -s)),MINGW64)
  # cgo accepts not '/c/path' but 'c:/path'
  PWD=$(shell pwd|sed s'@^/\([a-z]\)@\1:@')
else
  PWD=$(shell pwd)
endif
MCL_DIR?=$(PWD)/../mcl
include $(MCL_DIR)/common.mk
LIB_DIR=lib
OBJ_DIR=obj
EXE_DIR=bin
CFLAGS += -std=c++11
LDFLAGS += -lpthread

SRC_SRC=bls_c256.cpp bls_c384.cpp bls_c384_256.cpp
TEST_SRC=bls256_test.cpp bls384_test.cpp bls384_256_test.cpp bls_c256_test.cpp bls_c384_test.cpp bls_c384_256_test.cpp
SAMPLE_SRC=bls256_smpl.cpp bls384_smpl.cpp

CFLAGS+=-I$(MCL_DIR)/include
ifneq ($(MCL_MAX_BIT_SIZE),)
  CFLAGS+=-DMCL_MAX_BIT_SIZE=$(MCL_MAX_BIT_SIZE)
endif
ifeq ($(DISABLE_THREAD_TEST),1)
  CFLAGS+=-DDISABLE_THREAD_TEST
endif
ifeq ($(BLS_SWAP_G),1)
  CFLAGS+=-DBLS_SWAP_G
endif

BLS256_LIB=$(LIB_DIR)/libbls256.a
BLS384_LIB=$(LIB_DIR)/libbls384.a
BLS384_256_LIB=$(LIB_DIR)/libbls384_256.a
BLS256_SNAME=bls256
BLS384_SNAME=bls384
BLS384_256_SNAME=bls384_256
BLS256_SLIB=$(LIB_DIR)/lib$(BLS256_SNAME).$(LIB_SUF)
BLS384_SLIB=$(LIB_DIR)/lib$(BLS384_SNAME).$(LIB_SUF)
BLS384_256_SLIB=$(LIB_DIR)/lib$(BLS384_256_SNAME).$(LIB_SUF)
all: $(BLS256_LIB) $(BLS256_SLIB) $(BLS384_LIB) $(BLS384_SLIB) $(BLS384_256_LIB) $(BLS384_256_SLIB)

MCL_LIB=$(MCL_DIR)/lib/libmcl.a

$(MCL_LIB):
	$(MAKE) -C $(MCL_DIR)

$(BLS256_LIB): $(OBJ_DIR)/bls_c256.o
	$(AR) $@ $<
$(BLS384_LIB): $(OBJ_DIR)/bls_c384.o
	$(AR) $@ $<
$(BLS384_256_LIB): $(OBJ_DIR)/bls_c384_256.o
	$(AR) $@ $<

ifneq ($(findstring $(OS),mac/mingw64),)
  COMMON_LIB=$(GMP_LIB) $(OPENSSL_LIB) -lstdc++
  BLS256_SLIB_LDFLAGS+=$(COMMON_LIB)
  BLS384_SLIB_LDFLAGS+=$(COMMON_LIB)
  BLS384_256_SLIB_LDFLAGS+=$(COMMON_LIB)
endif
ifeq ($(OS),mingw64)
  CFLAGS+=-I$(MCL_DIR)
  BLS256_SLIB_LDFLAGS+=-Wl,--out-implib,$(LIB_DIR)/lib$(BLS256_SNAME).a
  BLS384_SLIB_LDFLAGS+=-Wl,--out-implib,$(LIB_DIR)/lib$(BLS384_SNAME).a
  BLS384_256_SLIB_LDFLAGS+=-Wl,--out-implib,$(LIB_DIR)/lib$(BLS384_256_SNAME).a
endif
$(BLS256_SLIB): $(OBJ_DIR)/bls_c256.o $(MCL_LIB)
	$(PRE)$(CXX) -shared -o $@ $< -L$(MCL_DIR)/lib -lmcl $(BLS256_SLIB_LDFLAGS)
$(BLS384_SLIB): $(OBJ_DIR)/bls_c384.o $(MCL_LIB)
	$(PRE)$(CXX) -shared -o $@ $< -L$(MCL_DIR)/lib -lmcl $(BLS384_SLIB_LDFLAGS)
$(BLS384_256_SLIB): $(OBJ_DIR)/bls_c384_256.o $(MCL_LIB)
	$(PRE)$(CXX) -shared -o $@ $< -L$(MCL_DIR)/lib -lmcl $(BLS384_256_SLIB_LDFLAGS)

VPATH=test sample src

.SUFFIXES: .cpp .d .exe

$(OBJ_DIR)/%.o: %.cpp
	$(PRE)$(CXX) $(CFLAGS) -c $< -o $@ -MMD -MP -MF $(@:.o=.d)

$(EXE_DIR)/%384_256_test.exe: $(OBJ_DIR)/%384_256_test.o $(BLS384_256_LIB) $(MCL_LIB)
	$(PRE)$(CXX) $< -o $@ $(BLS384_256_LIB) -L$(MCL_DIR)/lib -lmcl $(LDFLAGS)

$(EXE_DIR)/%384_test.exe: $(OBJ_DIR)/%384_test.o $(BLS384_LIB) $(MCL_LIB)
	$(PRE)$(CXX) $< -o $@ $(BLS384_LIB) -L$(MCL_DIR)/lib -lmcl $(LDFLAGS)

$(EXE_DIR)/%256_test.exe: $(OBJ_DIR)/%256_test.o $(BLS256_LIB) $(MCL_LIB)
	$(PRE)$(CXX) $< -o $@ $(BLS256_LIB) -L$(MCL_DIR)/lib -lmcl $(LDFLAGS)

# sample exe links libbls256.a
$(EXE_DIR)/%.exe: $(OBJ_DIR)/%.o $(BLS256_LIB) $(MCL_LIB)
	$(PRE)$(CXX) $< -o $@ $(BLS256_LIB) -L$(MCL_DIR)/lib -lmcl $(LDFLAGS)
ifeq ($(OS),mac)
	install_name_tool bin/bls_smpl.exe -change lib/libmcl.dylib $(MCL_DIR)/lib/libmcl.dylib
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
	@sh -ec 'for i in $(TEST_EXE); do echo $$i; env PATH=$$PATH:../mcl/lib $(LIBPATH_KEY)=../mcl/lib LSAN_OPTIONS=verbosity=1 log_threads=1 $$i; done'
	$(MAKE) sample_test

test: $(TEST_EXE)
	@echo test $(TEST_EXE)
	@sh -ec 'for i in $(TEST_EXE); do env PATH=$$PATH:../mcl/lib $(LIBPATH_KEY)=../mcl/lib $$i|grep "ctest:name"; done' > result.txt
	@grep -v "ng=0, exception=0" result.txt; if [ $$? -eq 1 ]; then echo "all unit tests succeed"; else exit 1; fi
	$(MAKE) sample_test

sample_test: $(EXE_DIR)/bls_smpl.exe
	env PATH=$$PATH:../mcl/lib $(LIBPATH_KEY)=../mcl/lib python bls_smpl.py

# PATH is for mingw, LD_LIBRARY_PATH is for linux, DYLD_LIBRARY_PATH is for mac
COMMON_LIB_PATH="../../../lib:../../../../mcl/lib"
PATH_VAL=$$PATH:$(COMMON_LIB_PATH) LD_LIBRARY_PATH=$(COMMON_LIB_PATH) DYLD_LIBRARY_PATH=$(COMMON_LIB_PATH) CGO_LDFLAGS="-L../../../lib" CGO_CFLAGS="-I$(PWD)/include -I$(MCL_DIR)/include"
test_go256: ffi/go/bls/bls.go ffi/go/bls/bls_test.go $(BLS256_SLIB)
	cd ffi/go/bls && env PATH=$(PATH_VAL) go test -tags bn256 .
test_go384: ffi/go/bls/bls.go ffi/go/bls/bls_test.go $(BLS384_SLIB)
	cd ffi/go/bls && env PATH=$(PATH_VAL) go test -tags bn384 .
test_go384_256: ffi/go/bls/bls.go ffi/go/bls/bls_test.go $(BLS384_256_SLIB)
	cd ffi/go/bls && env PATH=$(PATH_VAL) go test -tags bn384_256 .

test_go:
	$(MAKE) test_go256
	$(MAKE) test_go384
	$(MAKE) test_go384_256

EMCC_OPT=-I./include -I./src -I../mcl/include -I./ -Wall -Wextra
EMCC_OPT+=-O3 -DNDEBUG
EMCC_OPT+=-s WASM=1 -s NO_EXIT_RUNTIME=1 -s MODULARIZE=1 #-s ASSERTIONS=1
EMCC_OPT+=-DCYBOZU_MINIMUM_EXCEPTION
EMCC_OPT+=-s ABORTING_MALLOC=0
EMCC_OPT+=-DMCLBN_FP_UNIT_SIZE=6
JS_DEP=src/bls_c384.cpp ../mcl/src/fp.cpp Makefile

../bls-wasm/bls_c.js: $(JS_DEP)
	emcc -o $@ src/bls_c384.cpp ../mcl/src/fp.cpp $(EMCC_OPT) -DMCL_MAX_BIT_SIZE=384 -DMCL_USE_WEB_CRYPTO_API -s DISABLE_EXCEPTION_CATCHING=1 -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING -DMCL_DONT_USE_CSPRNG -fno-exceptions -MD -MP -MF obj/bls_c384.d

bls-wasm:
	$(MAKE) ../bls-wasm/bls_c.js

clean:
	$(RM) $(OBJ_DIR)/*.d $(OBJ_DIR)/*.o $(EXE_DIR)/*.exe $(GEN_EXE) $(ASM_SRC) $(ASM_OBJ) $(LLVM_SRC) $(BLS256_LIB) $(BLS256_SLIB) $(BLS384_LIB) $(BLS384_SLIB) $(BLS384_256_LIB) $(BLS384_256_SLIB)

ALL_SRC=$(SRC_SRC) $(TEST_SRC) $(SAMPLE_SRC)
DEPEND_FILE=$(addprefix $(OBJ_DIR)/, $(ALL_SRC:.cpp=.d))
-include $(DEPEND_FILE)

PREFIX?=/usr/local
install: lib/libbls256.a lib/libbls256.$(LIB_SUF) lib/libbls384.a lib/libbls384.$(LIB_SUF) lib/libbls384_256.a lib/libbls384_256.$(LIB_SUF)
	$(MKDIR) $(PREFIX)/include/bls
	cp -a include/bls/ $(PREFIX)/include/
	$(MKDIR) $(PREFIX)/lib
	cp -a lib/libbls256.a lib/libbls256.$(LIB_SUF) lib/libbls384.a lib/libbls384.$(LIB_SUF) lib/libbls384_256.a lib/libbls384_256.$(LIB_SUF) $(PREFIX)/lib/

.PHONY: test bls-wasm

# don't remove these files automatically
.SECONDARY: $(addprefix $(OBJ_DIR)/, $(ALL_SRC:.cpp=.o))

