#pragma once
/**
	@file
	@brief C interface of bls.hpp
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/

#include <stdint.h> // for uint64_t, uint8_t
#include <stdlib.h> // for size_t

#ifdef __cplusplus
extern "C" {
#endif

typedef struct blsSecretKey blsSecretKey;
typedef struct blsPublicKey blsPublicKey;
typedef struct blsSign blsSign;
typedef struct blsId blsId;

void blsInit(void);

blsId *blsIdCreate(void);
void blsIdDestroy(blsId *id);

// return 0 if success
int blsIdSetStr(blsId *id, const char *buf, size_t bufSize);

/*
	return written size
	otherwise 0
*/
size_t blsIdGetStr(const blsId *id, char *buf, size_t maxBufSize);
/*
	access p[0], p[1], p[2], p[3]
*/
void blsIdSet(blsId *id, const uint64_t *p);

blsSecretKey* blsSecretKeyCreate(void);
void blsSecretKeyDestroy(blsSecretKey *sec);
void blsSecretKeyPut(const blsSecretKey *sec);
int blsSecretKeySetStr(blsSecretKey *sec, const char *buf, size_t bufSize);
size_t blsSecretKeyGetStr(const blsSecretKey *sec, char *buf, size_t maxBufSize);
void blsSecretKeyAdd(blsSecretKey *sec, const blsSecretKey *rhs);

void blsSecretKeyInit(blsSecretKey *sec);
void blsSecretKeyGetPublicKey(const blsSecretKey *sec, blsPublicKey *pub);
void blsSecretKeySign(const blsSecretKey *sec, blsSign *sign, const char *m, size_t size);
void blsSecretKeySet(blsSecretKey *sec, const blsSecretKey* const *msk, size_t k, const blsId *id);
void blsSecretKeyRecover(blsSecretKey *sec, const blsSecretKey* const *secVec, const blsId *const *idVec, size_t n);

blsPublicKey *blsPublicKeyCreate(void);
void blsPublicKeyDestroy(blsPublicKey *pub);
void blsPublicKeyPut(const blsPublicKey *pub);
int blsPublicKeySetStr(blsPublicKey *pub, const char *buf, size_t bufSize);
size_t blsPublicKeyGetStr(const blsPublicKey *pub, char *buf, size_t maxBufSize);
void blsPublicKeyAdd(blsPublicKey *pub, const blsPublicKey *rhs);
void blsPublicKeySet(blsPublicKey *pub, const blsPublicKey *const *mpk, size_t k, const blsId *id);
void blsPublicKeyRecover(blsPublicKey *pub, const blsPublicKey *const *pubVec, const blsId *const *idVec, size_t n);

blsSign *blsSignCreate(void);
void blsSignDestroy(blsSign *sign);
void blsSignPut(const blsSign *sign);
int blsSignSetStr(blsSign *sign, const char *buf, size_t bufSize);
size_t blsSignGetStr(const blsSign *sign, char *buf, size_t maxBufSize);
void blsSignAdd(blsSign *sign, const blsSign *rhs);
void blsSignRecover(blsSign *sign, const blsSign *const *signVec, const blsId *const *idVec, size_t n);

int blsSignVerify(const blsSign *sign, const blsPublicKey *pub, const char *m, size_t size);

#ifdef __cplusplus
}
#endif
