#pragma once
/**
	@file
	@brief C interface of bls.hpp
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/
#ifndef BLS_MAX_OP_UNIT_SIZE
	#error "define BLS_MAX_OP_UNIT_SIZE 4(or 6)"
#endif

#include <stdint.h> // for uint64_t, uint8_t
#include <stdlib.h> // for size_t

#ifdef _MSC_VER
#ifdef BLS256_DLL_EXPORT
#define BLS256_DLL_API __declspec(dllexport)
#else
#define BLS256_DLL_API __declspec(dllimport)
#ifndef MCL_NO_AUTOLINK
	#pragma comment(lib, "bls_if.lib")
#endif
#endif
#else
#define BLS256_DLL_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
	BlsCurveFp254BNb = 0,
	BlsCurveFp382_1 = 1,
	BlsCurveFp382_2 = 2
};

// same value with bls.hpp
enum {
	BlsIoBin = 2, // binary number
	BlsIoDec = 10, // decimal number
	BlsIoHex = 16, // hexadecimal number
	BlsIoEcComp = 512 // fixed byte representation
};

typedef struct {
	uint64_t buf[BLS_MAX_OP_UNIT_SIZE];
} blsId;

typedef struct {
	uint64_t buf[BLS_MAX_OP_UNIT_SIZE];
} blsSecretKey;

typedef struct {
	uint64_t buf[BLS_MAX_OP_UNIT_SIZE * 2 * 3];
} blsPublicKey;

typedef struct {
	uint64_t buf[BLS_MAX_OP_UNIT_SIZE * 3];
} blsSign;

/*
	initialize this library
	call this once before using the other method
	@note init() is not thread safe
*/
BLS256_DLL_API void blsInit(int curve, int maxUnitSize);
BLS256_DLL_API size_t blsGetOpUnitSize(void);
// return strlen(buf) if success else 0
BLS256_DLL_API int blsGetCurveOrder(char *buf, size_t maxBufSize);
BLS256_DLL_API int blsGetFieldOrder(char *buf, size_t maxBufSize);

BLS256_DLL_API blsId *blsIdCreate(void);
BLS256_DLL_API void blsIdDestroy(blsId *id);
// return 1 if same else 0
BLS256_DLL_API int blsIdIsSame(const blsId *lhs, const blsId *rhs);
BLS256_DLL_API void blsIdPut(const blsId *id);
BLS256_DLL_API void blsIdCopy(blsId *dst, const blsId *src);

// return 0 if success
BLS256_DLL_API int blsIdSetStr(blsId *id, const char *buf, size_t bufSize, int ioMode);

/*
	return written byte size if ioMode = BlsIoComp
	return strlen(buf) if ioMode = 2, 10, 16 ; written byte size = strlen(buf) + 1
	return 0 otherwise
*/
BLS256_DLL_API size_t blsIdGetStr(const blsId *id, char *buf, size_t maxBufSize, int ioMode);
/*
	access p[0], ..., p[3] if 256-bit curve
	access p[0], ..., p[5] if 384-bit curve
*/
BLS256_DLL_API void blsIdSet(blsId *id, const uint64_t *p);

BLS256_DLL_API blsSecretKey* blsSecretKeyCreate(void);
BLS256_DLL_API void blsSecretKeyDestroy(blsSecretKey *sec);
// return 1 if same else 0
BLS256_DLL_API int blsSecretKeyIsSame(const blsSecretKey *lhs, const blsSecretKey *rhs);

BLS256_DLL_API void blsSecretKeyPut(const blsSecretKey *sec);
BLS256_DLL_API void blsSecretKeyCopy(blsSecretKey *dst, const blsSecretKey *src);
BLS256_DLL_API void blsSecretKeySetArray(blsSecretKey *sec, const uint64_t *p);
BLS256_DLL_API int blsSecretKeySetStr(blsSecretKey *sec, const char *buf, size_t bufSize, int ioMode);
/*
	return written byte size if ioMode = BlsIoComp
	return strlen(buf) if ioMode = 2, 10, 16 ; written byte size = strlen(buf) + 1
	return 0 otherwise
*/
BLS256_DLL_API size_t blsSecretKeyGetStr(const blsSecretKey *sec, char *buf, size_t maxBufSize, int ioMode);
BLS256_DLL_API void blsSecretKeyAdd(blsSecretKey *sec, const blsSecretKey *rhs);

BLS256_DLL_API void blsSecretKeyInit(blsSecretKey *sec);
BLS256_DLL_API void blsSecretKeyGetPublicKey(const blsSecretKey *sec, blsPublicKey *pub);
BLS256_DLL_API void blsSecretKeySign(const blsSecretKey *sec, blsSign *sign, const char *m, size_t size);
BLS256_DLL_API void blsSecretKeySet(blsSecretKey *sec, const blsSecretKey* msk, size_t k, const blsId *id);
BLS256_DLL_API void blsSecretKeyRecover(blsSecretKey *sec, const blsSecretKey *secVec, const blsId *idVec, size_t n);
BLS256_DLL_API void blsSecretKeyGetPop(const blsSecretKey *sec, blsSign *sign);

BLS256_DLL_API blsPublicKey *blsPublicKeyCreate(void);
BLS256_DLL_API void blsPublicKeyDestroy(blsPublicKey *pub);
// return 1 if same else 0
BLS256_DLL_API int blsPublicKeyIsSame(const blsPublicKey *lhs, const blsPublicKey *rhs);
BLS256_DLL_API void blsPublicKeyPut(const blsPublicKey *pub);
BLS256_DLL_API void blsPublicKeyCopy(blsPublicKey *dst, const blsPublicKey *src);
BLS256_DLL_API int blsPublicKeySetStr(blsPublicKey *pub, const char *buf, size_t bufSize, int ioMode);
/*
	return written byte size if ioMode = BlsIoComp
	return strlen(buf) if ioMode = 2, 10, 16 ; written byte size = strlen(buf) + 1
	return 0 otherwise
*/
BLS256_DLL_API size_t blsPublicKeyGetStr(const blsPublicKey *pub, char *buf, size_t maxBufSize, int ioMode);
BLS256_DLL_API void blsPublicKeyAdd(blsPublicKey *pub, const blsPublicKey *rhs);
BLS256_DLL_API void blsPublicKeySet(blsPublicKey *pub, const blsPublicKey *mpk, size_t k, const blsId *id);
BLS256_DLL_API void blsPublicKeyRecover(blsPublicKey *pub, const blsPublicKey *pubVec, const blsId *idVec, size_t n);

BLS256_DLL_API blsSign *blsSignCreate(void);
BLS256_DLL_API void blsSignDestroy(blsSign *sign);
// return 1 if same else 0
BLS256_DLL_API int blsSignIsSame(const blsSign *lhs, const blsSign *rhs);
BLS256_DLL_API void blsSignPut(const blsSign *sign);
BLS256_DLL_API void blsSignCopy(blsSign *dst, const blsSign *src);
BLS256_DLL_API int blsSignSetStr(blsSign *sign, const char *buf, size_t bufSize, int ioMode);
/*
	return written byte size if ioMode = BlsIoComp
	return strlen(buf) if ioMode = 2, 10, 16 ; written byte size = strlen(buf) + 1
	return 0 otherwise
*/
BLS256_DLL_API size_t blsSignGetStr(const blsSign *sign, char *buf, size_t maxBufSize, int ioMode);
BLS256_DLL_API void blsSignAdd(blsSign *sign, const blsSign *rhs);
BLS256_DLL_API void blsSignRecover(blsSign *sign, const blsSign *signVec, const blsId *idVec, size_t n);

BLS256_DLL_API int blsSignVerify(const blsSign *sign, const blsPublicKey *pub, const char *m, size_t size);

BLS256_DLL_API int blsSignVerifyPop(const blsSign *sign, const blsPublicKey *pub);

#ifdef __cplusplus
}
#endif
