include ../mcl/common.mk
LIB_DIR=lib
OBJ_DIR=obj
EXE_DIR=bin
CFLAGS += -std=c++11

SRC_SRC=bls.cpp bls_if.cpp
TEST_SRC=bls_test.cpp bls_if_test.cpp
SAMPLE_SRC=bls_smpl.cpp bls_tool.cpp

CFLAGS+=-I../mcl/include

sample_test: $(EXE_DIR)/bls_smpl.exe
	python bls_smpl.py

##################################################################
BLS_LIB=$(LIB_DIR)/libbls.a
all: $(BLS_LIB)
	go build .

LIB_OBJ=$(OBJ_DIR)/bls.o

$(BLS_LIB): $(LIB_OBJ)
	-$(MKDIR) $(@D)
	$(AR) $@ $(LIB_OBJ)

MCL_LIB=../mcl/lib/libmcl.a

$(MCL_LIB):
	$(MAKE) -C ../mcl

##################################################################

BLS_IF_LIB=$(LIB_DIR)/libbls_if.a

$(BLS_IF_LIB): $(LIB_OBJ) $(OBJ_DIR)/bls_if.o
	$(AR) $@ $(LIB_OBJ) $(OBJ_DIR)/bls_if.o

VPATH=test sample src

.SUFFIXES: .cpp .d .exe

$(OBJ_DIR)/%.o: %.cpp
	-$(MKDIR) $(@D)
	$(PRE)$(CXX) $(CFLAGS) -c $< -o $@ -MMD -MP -MF $(@:.o=.d)

$(EXE_DIR)/%.exe: $(OBJ_DIR)/%.o $(BLS_LIB) $(MCL_LIB)
	-$(MKDIR) $(@D)
	$(PRE)$(CXX) $< -o $@ $(BLS_LIB) $(LDFLAGS) -lmcl -L../mcl/lib

$(EXE_DIR)/bls_if_test.exe: $(OBJ_DIR)/bls_if_test.o $(BLS_LIB) $(MCL_LIB) $(BLS_IF_LIB)
	-$(MKDIR) $(@D)
	$(PRE)$(CXX) $< -o $@ $(BLS_LIB) $(BLS_IF_LIB) $(LDFLAGS) -lmcl -L../mcl/lib

SAMPLE_EXE=$(addprefix $(EXE_DIR)/,$(SAMPLE_SRC:.cpp=.exe))
sample: $(SAMPLE_EXE) $(BLS_LIB)

TEST_EXE=$(addprefix $(EXE_DIR)/,$(TEST_SRC:.cpp=.exe))
test: $(TEST_EXE)
	@echo test $(TEST_EXE)
	@sh -ec 'for i in $(TEST_EXE); do $$i|grep "ctest:name"; done' > result.txt
	@grep -v "ng=0, exception=0" result.txt || echo "all unit tests are ok"

clean:
	$(RM) $(BLS_LIB) $(OBJ_DIR)/* $(EXE_DIR)/*.exe $(GEN_EXE) $(ASM_SRC) $(ASM_OBJ) $(LIB_OBJ) $(LLVM_SRC)

ALL_SRC=$(SRC_SRC) $(TEST_SRC) $(SAMPLE_SRC)
DEPEND_FILE=$(addprefix $(OBJ_DIR)/, $(ALL_SRC:.cpp=.d))
-include $(DEPEND_FILE)

# don't remove these files automatically
.SECONDARY: $(addprefix $(OBJ_DIR)/, $(ALL_SRC:.cpp=.o))
 
