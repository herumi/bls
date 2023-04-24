LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_CPPFLAGS += $(ETH_CFLAGS)

LOCAL_CPP_EXTENSION := .cpp .ll
LOCAL_MODULE := bls384_256

ifeq ($(TARGET_ARCH_ABI),x86_64)
  MY_BIT := 64
#  LOCAL_CPPFLAGS += -fexceptions -fno-rtti
  LOCAL_CPPFLAGS += -DMCL_DONT_USE_XBYAK -fno-exceptions -fno-rtti
endif
ifeq ($(TARGET_ARCH_ABI),arm64-v8a)
  MY_BIT := 64
  LOCAL_CPPFLAGS += -DMCL_DONT_USE_XBYAK -fno-exceptions -fno-rtti
endif
ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
  MY_BIT := 32
  LOCAL_CPPFLAGS += -DMCL_DONT_USE_XBYAK -fno-exceptions -fno-rtti
endif
ifeq ($(TARGET_ARCH_ABI),x86)
  MY_BIT := 32
  LOCAL_CPPFLAGS += -DMCL_DONT_USE_XBYAK -fno-exceptions -fno-rtti
endif
ifeq ($(MY_BIT),64)
  LOCAL_CPPFLAGS += -DMCL_SIZEOF_UNIT=8
endif
ifeq ($(MY_BIT),32)
  LOCAL_CPPFLAGS += -DMCL_SIZEOF_UNIT=4
endif
MY_BASE_LL := $(LOCAL_PATH)/../../mcl/src/base$(MY_BIT).ll
ifeq ($(TARGET_ARCH_ABI),x86_64)
  MY_BINT := $(LOCAL_PATH)/../../mcl/src/asm/bint-x64-amd64.S
else
  MY_BINT := $(LOCAL_PATH)/../../mcl/src/bint$(MY_BIT).ll
endif
LOCAL_SRC_FILES :=  $(LOCAL_PATH)/../../src/bls_c384_256.cpp $(LOCAL_PATH)/../../mcl/src/fp.cpp $(MY_BASE_LL) $(MY_BINT)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../include $(LOCAL_PATH)/../../mcl/include
LOCAL_CPPFLAGS += -O3 -DNDEBUG -fPIC -DMCL_DONT_USE_OPENSSL -DMCL_USE_LLVM=1 -DMCL_MAX_BIT_SIZE=384 -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING -std=c++03
LOCAL_CPPFLAGS += -fno-threadsafe-statics
LOCAL_CPPFLAGS += -D_FORTIFY_SOURCE=0

#LOCAL_LDLIBS := -llog #-Wl,--no-warn-shared-textrel
ifeq ($(BLS_LIB_SHARED),1)
  include $(BUILD_SHARED_LIBRARY)
else
  include $(BUILD_STATIC_LIBRARY)
endif
