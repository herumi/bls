#pragma once
/**
	@file
	@brief C interface of bls.hpp
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/
#include <mcl/bn.h>

#ifdef _MSC_VER
	#ifdef BLS_DONT_EXPORT
		#define BLS_DLL_API
	#else
		#ifdef BLS_DLL_EXPORT
			#define BLS_DLL_API __declspec(dllexport)
		#else
			#define BLS_DLL_API __declspec(dllimport)
		#endif
	#endif
	#ifndef BLS_NO_AUTOLINK
		#if MCLBN_FP_UNIT_SIZE == 4
			#pragma comment(lib, "bls256.lib")
		#elif MCLBN_FP_UNIT_SIZE == 6
			#pragma comment(lib, "bls384.lib")
		#endif
	#endif
#elif defined(__EMSCRIPTEN__) && !defined(BLS_DONT_EXPORT)
	#define BLS_DLL_API __attribute__((used))
#elif defined(__wasm__) && !defined(BLS_DONT_EXPORT)
	#define BLS_DLL_API __attribute__((visibility("default")))
#else
	#define BLS_DLL_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	mclBnFr v;
} blsId;

typedef struct {
	mclBnFr v;
} blsSecretKey;

typedef struct {
	mclBnG2 v;
} blsPublicKey;

typedef struct {
	mclBnG1 v;
} blsSignature;

/*
	initialize this library
	call this once before using the other functions
	@param curve [in] enum value defined in mcl/bn.h
	@param maxUnitSize [in] MCLBN_FP_UNIT_SIZE (fixed)
	return 0 if success
	@note blsInit() is thread safe and serialized if it is called simultaneously
	but don't call it while using other functions.
*/
BLS_DLL_API int blsInit(int curve, int maxUnitSize);

BLS_DLL_API void blsIdSetInt(blsId *id, int x);

// return 0 if success
// mask buf with (1 << (bitLen(r) - 1)) - 1 if buf >= r
BLS_DLL_API int blsSecretKeySetLittleEndian(blsSecretKey *sec, const void *buf, mclSize bufSize);

BLS_DLL_API void blsGetPublicKey(blsPublicKey *pub, const blsSecretKey *sec);

// calculate the hash of m and sign the hash
BLS_DLL_API void blsSign(blsSignature *sig, const blsSecretKey *sec, const void *m, mclSize size);

// return 1 if valid
BLS_DLL_API int blsVerify(const blsSignature *sig, const blsPublicKey *pub, const void *m, mclSize size);

// sign the hash
BLS_DLL_API void blsSignHash(blsSignature *sig, const blsSecretKey *sec, const void *h, mclSize size);

// return 1 if valid
BLS_DLL_API int blsVerifyHash(const blsSignature *sig, const blsPublicKey *pub, const void *h, mclSize size);

// return 1 if valid, 0 if invalid or when duplicated hashes were provided
// verify an aggregated signature given the public keys and message hashes. No duplicate message hashes allowed
BLS_DLL_API int blsVerifyAggregatedHashes(const blsSignature *sig, const blsPublicKey *pubVec, const void *hashVec, mclSize hashSize, mclSize hashCount);

// return written byte size if success else 0
BLS_DLL_API mclSize blsIdSerialize(void *buf, mclSize maxBufSize, const blsId *id);
BLS_DLL_API mclSize blsSecretKeySerialize(void *buf, mclSize maxBufSize, const blsSecretKey *sec);
BLS_DLL_API mclSize blsPublicKeySerialize(void *buf, mclSize maxBufSize, const blsPublicKey *pub);
BLS_DLL_API mclSize blsSignatureSerialize(void *buf, mclSize maxBufSize, const blsSignature *sig);

// return read byte size if success else 0
BLS_DLL_API mclSize blsIdDeserialize(blsId *id, const void *buf, mclSize bufSize);
BLS_DLL_API mclSize blsSecretKeyDeserialize(blsSecretKey *sec, const void *buf, mclSize bufSize);
BLS_DLL_API mclSize blsPublicKeyDeserialize(blsPublicKey *pub, const void *buf, mclSize bufSize);
BLS_DLL_API mclSize blsSignatureDeserialize(blsSignature *sig, const void *buf, mclSize bufSize);

// return 1 if same else 0
BLS_DLL_API int blsIdIsEqual(const blsId *lhs, const blsId *rhs);
BLS_DLL_API int blsSecretKeyIsEqual(const blsSecretKey *lhs, const blsSecretKey *rhs);
BLS_DLL_API int blsPublicKeyIsEqual(const blsPublicKey *lhs, const blsPublicKey *rhs);
BLS_DLL_API int blsSignatureIsEqual(const blsSignature *lhs, const blsSignature *rhs);

// return 0 if success
BLS_DLL_API int blsSecretKeyShare(blsSecretKey *sec, const blsSecretKey* msk, mclSize k, const blsId *id);
BLS_DLL_API int blsPublicKeyShare(blsPublicKey *pub, const blsPublicKey *mpk, mclSize k, const blsId *id);

BLS_DLL_API int blsSecretKeyRecover(blsSecretKey *sec, const blsSecretKey *secVec, const blsId *idVec, mclSize n);
BLS_DLL_API int blsPublicKeyRecover(blsPublicKey *pub, const blsPublicKey *pubVec, const blsId *idVec, mclSize n);
BLS_DLL_API int blsSignatureRecover(blsSignature *sig, const blsSignature *sigVec, const blsId *idVec, mclSize n);

// add
BLS_DLL_API void blsSecretKeyAdd(blsSecretKey *sec, const blsSecretKey *rhs);
BLS_DLL_API void blsPublicKeyAdd(blsPublicKey *pub, const blsPublicKey *rhs);
BLS_DLL_API void blsSignatureAdd(blsSignature *sig, const blsSignature *rhs);

/*
	verify whether a point of an elliptic curve has order r
	This api affetcs setStr(), deserialize() for G2 on BN or G1/G2 on BLS12
	@param doVerify [in] does not verify if zero(default 1)
	Signature = G1, PublicKey = G2
*/
BLS_DLL_API void blsSignatureVerifyOrder(int doVerify);
BLS_DLL_API void blsPublicKeyVerifyOrder(int doVerify);
//	deserialize under VerifyOrder(true) = deserialize under VerifyOrder(false) + IsValidOrder
BLS_DLL_API int blsSignatureIsValidOrder(const blsSignature *sig);
BLS_DLL_API int blsPublicKeyIsValidOrder(const blsPublicKey *pub);

#ifndef BLS_MINIMUM_API

// sub
BLS_DLL_API void blsSecretKeySub(blsSecretKey *sec, const blsSecretKey *rhs);
BLS_DLL_API void blsPublicKeySub(blsPublicKey *pub, const blsPublicKey *rhs);
BLS_DLL_API void blsSignatureSub(blsSignature *sig, const blsSignature *rhs);

// not thread safe version (old blsInit)
BLS_DLL_API int blsInitNotThreadSafe(int curve, int maxUnitSize);

BLS_DLL_API mclSize blsGetOpUnitSize(void);
// return strlen(buf) if success else 0
BLS_DLL_API int blsGetCurveOrder(char *buf, mclSize maxBufSize);
BLS_DLL_API int blsGetFieldOrder(char *buf, mclSize maxBufSize);

// return bytes for serialized G1(=Fp)
BLS_DLL_API int blsGetG1ByteSize(void);

// return bytes for serialized Fr
BLS_DLL_API int blsGetFrByteSize(void);

// get a generator of G2
BLS_DLL_API void blsGetGeneratorOfG2(blsPublicKey *pub);

// return 0 if success
BLS_DLL_API int blsIdSetDecStr(blsId *id, const char *buf, mclSize bufSize);
BLS_DLL_API int blsIdSetHexStr(blsId *id, const char *buf, mclSize bufSize);

/*
	return strlen(buf) if success else 0
	buf is '\0' terminated
*/
BLS_DLL_API mclSize blsIdGetDecStr(char *buf, mclSize maxBufSize, const blsId *id);
BLS_DLL_API mclSize blsIdGetHexStr(char *buf, mclSize maxBufSize, const blsId *id);

// hash buf and set
BLS_DLL_API int blsHashToSecretKey(blsSecretKey *sec, const void *buf, mclSize bufSize);
#ifndef MCL_DONT_USE_CSPRNG
/*
	set secretKey if system has /dev/urandom or CryptGenRandom
	return 0 if success else -1
*/
BLS_DLL_API int blsSecretKeySetByCSPRNG(blsSecretKey *sec);
#endif

BLS_DLL_API void blsGetPop(blsSignature *sig, const blsSecretKey *sec);

BLS_DLL_API int blsVerifyPop(const blsSignature *sig, const blsPublicKey *pub);
//////////////////////////////////////////////////////////////////////////
// the following apis will be removed

// mask buf with (1 << (bitLen(r) - 1)) - 1 if buf >= r
BLS_DLL_API int blsIdSetLittleEndian(blsId *id, const void *buf, mclSize bufSize);
/*
	return written byte size if success else 0
*/
BLS_DLL_API mclSize blsIdGetLittleEndian(void *buf, mclSize maxBufSize, const blsId *id);

// return 0 if success
BLS_DLL_API int blsSecretKeySetDecStr(blsSecretKey *sec, const char *buf, mclSize bufSize);
BLS_DLL_API int blsSecretKeySetHexStr(blsSecretKey *sec, const char *buf, mclSize bufSize);
/*
	return written byte size if success else 0
*/
BLS_DLL_API mclSize blsSecretKeyGetLittleEndian(void *buf, mclSize maxBufSize, const blsSecretKey *sec);
/*
	return strlen(buf) if success else 0
	buf is '\0' terminated
*/
BLS_DLL_API mclSize blsSecretKeyGetDecStr(char *buf, mclSize maxBufSize, const blsSecretKey *sec);
BLS_DLL_API mclSize blsSecretKeyGetHexStr(char *buf, mclSize maxBufSize, const blsSecretKey *sec);
BLS_DLL_API int blsPublicKeySetHexStr(blsPublicKey *pub, const char *buf, mclSize bufSize);
BLS_DLL_API mclSize blsPublicKeyGetHexStr(char *buf, mclSize maxBufSize, const blsPublicKey *pub);
BLS_DLL_API int blsSignatureSetHexStr(blsSignature *sig, const char *buf, mclSize bufSize);
BLS_DLL_API mclSize blsSignatureGetHexStr(char *buf, mclSize maxBufSize, const blsSignature *sig);

/*
	Diffie Hellman key exchange
	out = sec * pub
*/
BLS_DLL_API void blsDHKeyExchange(blsPublicKey *out, const blsSecretKey *sec, const blsPublicKey *pub);

#endif // BLS_MINIMUM_API

#ifdef __cplusplus
}
#endif
