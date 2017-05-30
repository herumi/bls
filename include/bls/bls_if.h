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
#ifdef BLS_DLL_EXPORT
#define BLS_DLL_API __declspec(dllexport)
#else
#define BLS_DLL_API __declspec(dllimport)
#ifndef BLS_NO_AUTOLINK
	#if BLS_MAX_OP_UNIT_SIZE == 4
		#pragma comment(lib, "bls_if256.lib")
	#endif
#endif
#endif
#else
#define BLS_DLL_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
	blsCurveFp254BNb = 0,
	blsCurveFp382_1 = 1,
	blsCurveFp382_2 = 2
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
} blsSignature;

/*
	initialize this library
	call this once before using the other method
	return 0 if success
	@note init() is not thread safe
*/
BLS_DLL_API int blsInit(int curve, int maxUnitSize);
BLS_DLL_API size_t blsGetOpUnitSize(void);
// return strlen(buf) if success else 0
BLS_DLL_API int blsGetCurveOrder(char *buf, size_t maxBufSize);
BLS_DLL_API int blsGetFieldOrder(char *buf, size_t maxBufSize);

// return 1 if same else 0
BLS_DLL_API int blsIdIsEqual(const blsId *lhs, const blsId *rhs);

// mask buf with (1 << (bitLen(r) - 1)) - 1 if buf >= r
// return 0 if success
BLS_DLL_API int blsIdSetLittleEndian(blsId *id, const void *buf, size_t bufSize);
BLS_DLL_API int blsIdSetDecStr(blsId *id, const char *buf, size_t bufSize);
BLS_DLL_API int blsIdSetHexStr(blsId *id, const char *buf, size_t bufSize);

/*
	return written byte size if success else 0
*/
BLS_DLL_API size_t blsIdGetLittleEndian(void *buf, size_t maxBufSize, const blsId *id);
/*
	return strlen(buf) if success else 0
	buf is '\0' terminated
*/
BLS_DLL_API size_t blsIdGetDecStr(char *buf, size_t maxBufSize, const blsId *id);
BLS_DLL_API size_t blsIdGetHexStr(char *buf, size_t maxBufSize, const blsId *id);

// return 1 if same else 0
BLS_DLL_API int blsSecretKeyIsEqual(const blsSecretKey *lhs, const blsSecretKey *rhs);

// mask buf with (1 << (bitLen(r) - 1)) - 1 if buf >= r
// return 0 if success
BLS_DLL_API int blsSecretKeySetLittleEndian(blsSecretKey *sec, const void *buf, size_t bufSize);
BLS_DLL_API int blsSecretKeySetDecStr(blsSecretKey *sec, const char *buf, size_t bufSize);
BLS_DLL_API int blsSecretKeySetHexStr(blsSecretKey *sec, const char *buf, size_t bufSize);
/*
	return written byte size if success else 0
*/
BLS_DLL_API size_t blsSecretKeyGetLittleEndian(void *buf, size_t maxBufSize, const blsSecretKey *sec);
/*
	hash buf and set
*/
BLS_DLL_API int blsHashToSecretKey(blsSecretKey *sec, const void *buf, size_t bufSize);
/*
	set secretKey if system has /dev/urandom or CryptGenRandom
	return 0 if success else -1
*/
BLS_DLL_API int blsSecretKeySetByCSPRNG(blsSecretKey *sec);
/*
	return strlen(buf) if success else 0
	buf is '\0' terminated
*/
BLS_DLL_API size_t blsSecretKeyGetDecStr(char *buf, size_t maxBufSize, const blsSecretKey *sec);
BLS_DLL_API size_t blsSecretKeyGetHexStr(char *buf, size_t maxBufSize, const blsSecretKey *sec);
BLS_DLL_API void blsSecretKeyAdd(blsSecretKey *sec, const blsSecretKey *rhs);

BLS_DLL_API void blsGetPublicKey(blsPublicKey *pub, const blsSecretKey *sec);
BLS_DLL_API void blsSign(blsSignature *sig, const blsSecretKey *sec, const char *m, size_t size);
// return 0 if success
BLS_DLL_API int blsSecretKeyShare(blsSecretKey *sec, const blsSecretKey* msk, size_t k, const blsId *id);
// return 0 if success
BLS_DLL_API int blsSecretKeyRecover(blsSecretKey *sec, const blsSecretKey *secVec, const blsId *idVec, size_t n);
BLS_DLL_API void blsGetPop(blsSignature *sig, const blsSecretKey *sec);

// return 1 if same else 0
BLS_DLL_API int blsPublicKeyIsEqual(const blsPublicKey *lhs, const blsPublicKey *rhs);
// return 0 if success
BLS_DLL_API int blsPublicKeyDeserialize(blsPublicKey *pub, const void *buf, size_t bufSize);
/*
	return written byte size if success else 0
*/
BLS_DLL_API size_t blsPublicKeySerialize(void *buf, size_t maxBufSize, const blsPublicKey *pub);
BLS_DLL_API int blsPublicKeySetHexStr(blsPublicKey *pub, const char *buf, size_t bufSize);
BLS_DLL_API size_t blsPublicKeyGetHexStr(char *buf, size_t maxBufSize, const blsPublicKey *pub);
BLS_DLL_API void blsPublicKeyAdd(blsPublicKey *pub, const blsPublicKey *rhs);
// return 0 if success
BLS_DLL_API int blsPublicKeyShare(blsPublicKey *pub, const blsPublicKey *mpk, size_t k, const blsId *id);
// return 0 if success
BLS_DLL_API int blsPublicKeyRecover(blsPublicKey *pub, const blsPublicKey *pubVec, const blsId *idVec, size_t n);

// return 1 if same else 0
BLS_DLL_API int blsSignatureIsEqual(const blsSignature *lhs, const blsSignature *rhs);

// return 0 if success
BLS_DLL_API int blsSignatureDeserialize(blsSignature *sig, const void *buf, size_t bufSize);
/*
	return written byte size if success else 0
*/
BLS_DLL_API size_t blsSignatureSerialize(void *buf, size_t maxBufSize, const blsSignature *sig);
BLS_DLL_API int blsSignatureSetHexStr(blsSignature *sig, const char *buf, size_t bufSize);
BLS_DLL_API size_t blsSignatureGetHexStr(char *buf, size_t maxBufSize, const blsSignature *sig);
BLS_DLL_API void blsSignatureAdd(blsSignature *sig, const blsSignature *rhs);
// return 0 if success
BLS_DLL_API int blsSignatureRecover(blsSignature *sig, const blsSignature *sigVec, const blsId *idVec, size_t n);
BLS_DLL_API int blsVerify(const blsSignature *sig, const blsPublicKey *pub, const char *m, size_t size);

BLS_DLL_API int blsVerifyPop(const blsSignature *sig, const blsPublicKey *pub);

#ifdef __cplusplus
}
#endif
