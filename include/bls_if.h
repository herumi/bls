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
void blsIdPut(const blsId *id);

// return 0 if success
int blsIdSetStr(blsId *id, const char *buf, size_t bufSize);

/*
	return written size
	otherwise 0
*/
size_t blsIdGetStr(const blsId *id, char *buf, size_t maxBufSize);

void blsIdSet(blsId *id, const uint64_t *p);

blsSecretKey* blsSecretKeyCreate(void);
void blsSecretKeyDestroy(blsSecretKey *sec);
void blsSecretKeyPut(const blsSecretKey *sec);

void blsSecretKeyInit(blsSecretKey *sec);
void blsSecretKeyGetPublicKey(const blsSecretKey *sec, blsPublicKey *pub);
void blsSecretKeySign(const blsSecretKey *sec, blsSign *sign, const char *m, size_t size);

blsPublicKey *blsPublicKeyCreate(void);
void blsPublicKeyDestroy(blsPublicKey *pub);
void blsPublicKeyPut(const blsPublicKey *pub);

blsSign *blsSignCreate(void);
void blsSignDestroy(blsSign *sign);
void blsSignPut(const blsSign *sign);

int blsSignVerify(const blsSign *sign, const blsPublicKey *pub, const char *m, size_t size);

#ifdef __cplusplus
}
#endif
