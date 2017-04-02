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
	#pragma comment(lib, "bls_if.lib")
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
	BlsCurveFp254BNb = 0,
	BlsCurveFp382_1 = 1,
	BlsCurveFp382_2 = 2
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

void blsInit(int curve, int maxUnitSize);
size_t blsGetOpUnitSize(void);

blsId *blsIdCreate(void);
void blsIdDestroy(blsId *id);
void blsIdPut(const blsId *id);
void blsIdCopy(blsId *dst, const blsId *src);

// return 0 if success
int blsIdSetStr(blsId *id, const char *buf, size_t bufSize);

/*
	return written size
	otherwise 0
*/
size_t blsIdGetStr(const blsId *id, char *buf, size_t maxBufSize);
/*
	access p[0], ..., p[3] if 256-bit curve
	access p[0], ..., p[5] if 384-bit curve
*/
void blsIdSet(blsId *id, const uint64_t *p);

blsSecretKey* blsSecretKeyCreate(void);
void blsSecretKeyDestroy(blsSecretKey *sec);
void blsSecretKeyPut(const blsSecretKey *sec);
void blsSecretKeyCopy(blsSecretKey *dst, const blsSecretKey *src);
void blsSecretKeySetArray(blsSecretKey *sec, const uint64_t *p);
int blsSecretKeySetStr(blsSecretKey *sec, const char *buf, size_t bufSize);
size_t blsSecretKeyGetStr(const blsSecretKey *sec, char *buf, size_t maxBufSize);
void blsSecretKeyAdd(blsSecretKey *sec, const blsSecretKey *rhs);

void blsSecretKeyInit(blsSecretKey *sec);
void blsSecretKeyGetPublicKey(const blsSecretKey *sec, blsPublicKey *pub);
void blsSecretKeySign(const blsSecretKey *sec, blsSign *sign, const char *m, size_t size);
void blsSecretKeySet(blsSecretKey *sec, const blsSecretKey* msk, size_t k, const blsId *id);
void blsSecretKeyRecover(blsSecretKey *sec, const blsSecretKey *secVec, const blsId *idVec, size_t n);
void blsSecretKeyGetPop(const blsSecretKey *sec, blsSign *sign);

blsPublicKey *blsPublicKeyCreate(void);
void blsPublicKeyDestroy(blsPublicKey *pub);
void blsPublicKeyPut(const blsPublicKey *pub);
void blsPublicKeyCopy(blsPublicKey *dst, const blsPublicKey *src);
int blsPublicKeySetStr(blsPublicKey *pub, const char *buf, size_t bufSize);
size_t blsPublicKeyGetStr(const blsPublicKey *pub, char *buf, size_t maxBufSize);
void blsPublicKeyAdd(blsPublicKey *pub, const blsPublicKey *rhs);
void blsPublicKeySet(blsPublicKey *pub, const blsPublicKey *mpk, size_t k, const blsId *id);
void blsPublicKeyRecover(blsPublicKey *pub, const blsPublicKey *pubVec, const blsId *idVec, size_t n);

blsSign *blsSignCreate(void);
void blsSignDestroy(blsSign *sign);
void blsSignPut(const blsSign *sign);
void blsSignCopy(blsSign *dst, const blsSign *src);
int blsSignSetStr(blsSign *sign, const char *buf, size_t bufSize);
size_t blsSignGetStr(const blsSign *sign, char *buf, size_t maxBufSize);
void blsSignAdd(blsSign *sign, const blsSign *rhs);
void blsSignRecover(blsSign *sign, const blsSign *signVec, const blsId *idVec, size_t n);

int blsSignVerify(const blsSign *sign, const blsPublicKey *pub, const char *m, size_t size);

int blsSignVerifyPop(const blsSign *sign, const blsPublicKey *pub);

#ifdef __cplusplus
}
#endif
