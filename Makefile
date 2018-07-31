include ../mcl/common.mk
LIB_DIR=lib
OBJ_DIR=obj
EXE_DIR=bin
CFLAGS += -std=c++11
LDFLAGS += -lpthread

SRC_SRC=bls.cpp bls_c.cpp
TEST_SRC=bls_test.cpp bls_c384_test.cpp
SAMPLE_SRC=bls_smpl.cpp

CFLAGS+=-I../mcl/include
UNIT?=6
ifeq ($(UNIT),4)
  CFLAGS+=-D"MCLBN_FP_UNIT_SIZE=4"
  GO_TAG=bn256
endif
ifeq ($(UNIT),6)
  CFLAGS+=-D"MCLBN_FP_UNIT_SIZE=6"
  GO_TAG=bn384
endif
ifneq ($(MCL_MAX_BIT_SIZE),)
  CFLAGS+=-DMCL_MAX_BIT_SIZE=$(MCL_MAX_BIT_SIZE)
endif
ifeq ($(DISABLE_THREAD_TEST),1)
  CFLAGS+=-DDISABLE_THREAD_TEST
endif

SHARE_BASENAME_SUF?=_dy
##################################################################
BLS_LIB=$(LIB_DIR)/libbls.a

LIB_OBJ=$(OBJ_DIR)/bls.o

$(BLS_LIB): $(LIB_OBJ)
	$(AR) $@ $(LIB_OBJ)

MCL_LIB=../mcl/lib/libmcl.a
BN384_LIB=../mcl/lib/libmclbn384.a

$(MCL_LIB):
	$(MAKE) -C ../mcl

##################################################################

BLS384_LIB=$(LIB_DIR)/libbls384.a
BLS384_SNAME=bls384$(SHARE_BASENAME_SUF)
BLS384_SLIB=$(LIB_DIR)/lib$(BLS384_SNAME).$(LIB_SUF)
all: $(BLS_LIB) $(BLS384_SLIB)

$(BLS384_LIB): $(LIB_OBJ) $(OBJ_DIR)/bls_c384.o
	$(AR) $@ $(LIB_OBJ) $(OBJ_DIR)/bls_c384.o

ifneq ($(findstring $(OS),mac/mingw64),)
  BLS384_SLIB_LDFLAGS+=-lgmpxx -lgmp -lcrypto -lstdc++
endif
ifeq ($(OS),mingw64)
  BLS384_SLIB_LDFLAGS+=-Wl,--out-implib,$(LIB_DIR)/lib$(BLS384_SNAME).a
endif
$(BLS384_SLIB): $(OBJ_DIR)/bls_c384.o $(MCL_LIB)
	$(PRE)$(CXX) -shared -o $@ $(OBJ_DIR)/bls_c384.o $(MCL_LIB) $(BLS384_SLIB_LDFLAGS)

VPATH=test sample src

.SUFFIXES: .cpp .d .exe

$(OBJ_DIR)/%.o: %.cpp
	$(PRE)$(CXX) $(CFLAGS) -c $< -o $@ -MMD -MP -MF $(@:.o=.d)

$(OBJ_DIR)/bls_c384.o: bls_c.cpp
	$(PRE)$(CXX) $(CFLAGS) -c $< -o $@ -MMD -MP -MF $(@:.o=.d) -DMBN_FP_UNIT_SIZE=6

$(EXE_DIR)/%.exe: $(OBJ_DIR)/%.o $(BLS_LIB) $(BLS384_LIB) $(MCL_LIB)
	$(PRE)$(CXX) $< -o $@ $(BLS_LIB) $(BLS384_LIB) -lmcl -L../mcl/lib $(LDFLAGS)

SAMPLE_EXE=$(addprefix $(EXE_DIR)/,$(SAMPLE_SRC:.cpp=.exe))
sample: $(SAMPLE_EXE) $(BLS_LIB)

TEST_EXE=$(addprefix $(EXE_DIR)/,$(TEST_SRC:.cpp=.exe))
test: $(TEST_EXE)
	@echo test $(TEST_EXE)
	@sh -ec 'for i in $(TEST_EXE); do $$i|grep "ctest:name"; done' > result.txt
	@grep -v "ng=0, exception=0" result.txt; if [ $$? -eq 1 ]; then echo "all unit tests succeed"; else exit 1; fi
	$(MAKE) sample_test

sample_test: $(EXE_DIR)/bls_smpl.exe
	python bls_smpl.py

ifeq ($(OS),mac)
  MAC_GO_LDFLAGS="-ldflags=-s"
endif
# PATH is for mingw, LD_RUN_PATH is for linux
test_go: ffi/go/bls/bls.go ffi/go/bls/bls_test.go $(BLS384_SLIB)
	cd ffi/go/bls && env PATH=$$PATH:../../../lib LD_RUN_PATH="../../../lib" go test $(MAC_GO_LDFLAGS) .

EMCC_OPT=-I./include -I./src -I../cybozulib/include -I../mcl/include -I./ -Wall -Wextra
EMCC_OPT+=-O3 -DNDEBUG
EMCC_OPT+=-s WASM=1 -s NO_EXIT_RUNTIME=1 -s MODULARIZE=1 #-s ASSERTIONS=1
EMCC_OPT+=-DCYBOZU_MINIMUM_EXCEPTION
EMCC_OPT+=-s ABORTING_MALLOC=0
EMCC_OPT+=-DMCLBN_FP_UNIT_SIZE=6
JS_DEP=src/bls_c.cpp ../mcl/src/fp.cpp Makefile

../bls-wasm/bls_c.js: $(JS_DEP)
	emcc -o $@ src/bls_c.cpp ../mcl/src/fp.cpp $(EMCC_OPT) -DMCL_MAX_BIT_SIZE=384 -DMCL_USE_WEB_CRYPTO_API -s DISABLE_EXCEPTION_CATCHING=1 -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING -DMCL_DONT_USE_CSPRNG -fno-exceptions -MD -MP -MF obj/bls_c.d

bls-wasm:
	$(MAKE) ../bls-wasm/bls_c.js

clean:
	$(RM) $(BLS_LIB) $(OBJ_DIR)/*.d $(OBJ_DIR)/*.o $(EXE_DIR)/*.exe $(GEN_EXE) $(ASM_SRC) $(ASM_OBJ) $(LIB_OBJ) $(LLVM_SRC) $(BLS384_SLIB)

ALL_SRC=$(SRC_SRC) $(TEST_SRC) $(SAMPLE_SRC)
DEPEND_FILE=$(addprefix $(OBJ_DIR)/, $(ALL_SRC:.cpp=.d))
-include $(DEPEND_FILE)

.PHONY: test bls-wasm

# don't remove these files automatically
.SECONDARY: $(addprefix $(OBJ_DIR)/, $(ALL_SRC:.cpp=.o))

