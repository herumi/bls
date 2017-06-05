#include "../mcl/src/bn_c_impl.hpp"
#include "bls/bls.hpp"
#define BLS_DLL_EXPORT
#include "bls/bls.h"
#include <iostream>
#include <sstream>
#include <memory.h>

size_t checkAndCopy(char *buf, size_t maxBufSize, const std::string& s)
{
	if (s.size() > maxBufSize + 1) {
		return 0;
	}
	memcpy(buf, s.c_str(), s.size());
	buf[s.size()] = '\0';
	return s.size();
}

int blsInit(int curve, int maxUnitSize)
	try
{
	mclBn_init(curve, maxUnitSize);
	bls::init(curve, maxUnitSize); // QQQ
	return 0;
} catch (std::exception&) {
	return -1;
}
size_t blsGetOpUnitSize()
{
	return bls::getOpUnitSize();
}

int blsGetCurveOrder(char *buf, size_t maxBufSize)
	try
{
	std::string s;
	bls::getCurveOrder(s);
	return (int)checkAndCopy(buf, maxBufSize, s);
} catch (std::exception&) {
	return 0;
}

int blsGetFieldOrder(char *buf, size_t maxBufSize)
	try
{
	std::string s;
	bls::getFieldOrder(s);
	return (int)checkAndCopy(buf, maxBufSize, s);
} catch (std::exception&) {
	return 0;
}

int blsIdIsEqual(const blsId *lhs, const blsId *rhs)
{
	return mclBnFr_isEqual(&lhs->v, &rhs->v);
}
int blsIdSetLittleEndian(blsId *id, const void *buf, size_t bufSize)
{
	return mclBnFr_setLittleEndian(&id->v, buf, bufSize);
}
int blsIdSetDecStr(blsId *id, const char *buf, size_t bufSize)
{
	return mclBnFr_setStr(&id->v, buf, bufSize, 10);
}
int blsIdSetHexStr(blsId *id, const char *buf, size_t bufSize)
{
	return mclBnFr_setStr(&id->v, buf, bufSize, 16);
}
size_t blsIdGetLittleEndian(void *buf, size_t maxBufSize, const blsId *id)
{
	return mclBnFr_serialize(buf, maxBufSize, &id->v);
}
size_t blsIdGetDecStr(char *buf, size_t maxBufSize, const blsId *id)
{
	return mclBnFr_getStr(buf, maxBufSize, &id->v, 10);
}
size_t blsIdGetHexStr(char *buf, size_t maxBufSize, const blsId *id)
{
	return mclBnFr_getStr(buf, maxBufSize, &id->v, 16);
}
int blsSecretKeyIsEqual(const blsSecretKey *lhs, const blsSecretKey *rhs)
{
	return mclBnFr_isEqual(&lhs->v, &rhs->v);
}
int blsSecretKeySetLittleEndian(blsSecretKey *sec, const void *buf, size_t bufSize)
{
	return mclBnFr_setLittleEndian(&sec->v, buf, bufSize);
}
int blsSecretKeySetDecStr(blsSecretKey *sec, const char *buf, size_t bufSize)
{
	return mclBnFr_setStr(&sec->v, buf, bufSize, 10);
}
int blsSecretKeySetHexStr(blsSecretKey *sec, const char *buf, size_t bufSize)
{
	return mclBnFr_setStr(&sec->v, buf, bufSize, 16);
}
size_t blsSecretKeyGetLittleEndian(void *buf, size_t maxBufSize, const blsSecretKey *sec)
{
	return mclBnFr_serialize(buf, maxBufSize, &sec->v);
}
size_t blsSecretKeyGetDecStr(char *buf, size_t maxBufSize, const blsSecretKey *sec)
{
	return mclBnFr_getStr(buf, maxBufSize, &sec->v, 10);
}
size_t blsSecretKeyGetHexStr(char *buf, size_t maxBufSize, const blsSecretKey *sec)
{
	return mclBnFr_getStr(buf, maxBufSize, &sec->v, 16);
}

int blsHashToSecretKey(blsSecretKey *sec, const void *buf, size_t bufSize)
{
	return mclBnFr_setHashOf(&sec->v, buf, bufSize);
}

int blsSecretKeySetByCSPRNG(blsSecretKey *sec)
{
	return mclBnFr_setByCSPRNG(&sec->v);
}
void blsSecretKeyAdd(blsSecretKey *sec, const blsSecretKey *rhs)
{
	((bls::SecretKey*)sec)->add(*(const bls::SecretKey*)rhs);
}

void blsGetPublicKey(blsPublicKey *pub, const blsSecretKey *sec)
{
	((const bls::SecretKey*)sec)->getPublicKey(*(bls::PublicKey*)pub);
}
void blsSign(blsSignature *sig, const blsSecretKey *sec, const char *m, size_t size)
{
	((const bls::SecretKey*)sec)->sign(*(bls::Signature*)sig, std::string(m, size));
}
int blsSecretKeyShare(blsSecretKey *sec, const blsSecretKey* msk, size_t k, const blsId *id)
	try
{
	((bls::SecretKey*)sec)->set((const bls::SecretKey *)msk, k, *(const bls::Id*)id);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsSecretKeyShare %s\n", e.what());
	return -1;
}

int blsSecretKeyRecover(blsSecretKey *sec, const blsSecretKey *secVec, const blsId *idVec, size_t n)
	try
{
	((bls::SecretKey*)sec)->recover((const bls::SecretKey *)secVec, (const bls::Id *)idVec, n);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsSecretKeyRecover %s\n", e.what());
	return -1;
}

void blsGetPop(blsSignature *sig, const blsSecretKey *sec)
{
	((const bls::SecretKey*)sec)->getPop(*(bls::Signature*)sig);
}

int blsPublicKeyIsEqual(const blsPublicKey *lhs, const blsPublicKey *rhs)
{
	return mclBnG2_isEqual(&lhs->v, &rhs->v);
}
int blsPublicKeyDeserialize(blsPublicKey *pub, const void *buf, size_t bufSize)
{
	return mclBnG2_deserialize(&pub->v, buf, bufSize);
}
size_t blsPublicKeySerialize(void *buf, size_t maxBufSize, const blsPublicKey *pub)
{
	return mclBnG2_serialize(buf, maxBufSize, &pub->v);
}
int blsPublicKeySetHexStr(blsPublicKey *pub, const char *buf, size_t bufSize)
{
	return mclBnG2_setStr(&pub->v, buf, bufSize, 16);
}
size_t blsPublicKeyGetHexStr(char *buf, size_t maxBufSize, const blsPublicKey *pub)
{
	return mclBnG2_getStr(buf, maxBufSize, &pub->v, 16);
}
void blsPublicKeyAdd(blsPublicKey *pub, const blsPublicKey *rhs)
{
	((bls::PublicKey*)pub)->add(*(const bls::PublicKey*)rhs);
}
int blsPublicKeyShare(blsPublicKey *pub, const blsPublicKey *mpk, size_t k, const blsId *id)
	try
{
	((bls::PublicKey*)pub)->set((const bls::PublicKey*)mpk, k, *(const bls::Id*)id);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsPublicKeyShare %s\n", e.what());
	return -1;
}
int blsPublicKeyRecover(blsPublicKey *pub, const blsPublicKey *pubVec, const blsId *idVec, size_t n)
	try
{
	((bls::PublicKey*)pub)->recover((const bls::PublicKey*)pubVec, (const bls::Id*)idVec, n);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsPublicKeyRecover %s\n", e.what());
	return -1;
}

int blsSignatureIsEqual(const blsSignature *lhs, const blsSignature *rhs)
{
	return mclBnG1_isEqual(&lhs->v, &rhs->v);
}
int blsSignatureDeserialize(blsSignature *sig, const void *buf, size_t bufSize)
{
	return mclBnG1_deserialize(&sig->v, buf, bufSize);
}
int blsSignatureSetHexStr(blsSignature *sig, const char *buf, size_t bufSize)
{
	return mclBnG1_setStr(&sig->v, buf, bufSize, 16);
}
size_t blsSignatureGetHexStr(char *buf, size_t maxBufSize, const blsSignature *sig)
{
	return mclBnG1_getStr(buf, maxBufSize, &sig->v, 16);
}
size_t blsSignatureSerialize(void *buf, size_t maxBufSize, const blsSignature *sig)
{
	return mclBnG1_serialize(buf, maxBufSize, &sig->v);
}
void blsSignatureAdd(blsSignature *sig, const blsSignature *rhs)
{
	((bls::Signature*)sig)->add(*(const bls::Signature*)rhs);
}
int blsSignatureRecover(blsSignature *sig, const blsSignature *sigVec, const blsId *idVec, size_t n)
	try
{
	((bls::Signature*)sig)->recover((const bls::Signature*)sigVec, (const bls::Id*)idVec, n);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsSignatureRecover %s\n", e.what());
	return -1;
}

int blsVerify(const blsSignature *sig, const blsPublicKey *pub, const char *m, size_t size)
{
	return ((const bls::Signature*)sig)->verify(*(const bls::PublicKey*)pub, std::string(m, size));
}

int blsVerifyPop(const blsSignature *sig, const blsPublicKey *pub)
{
	return ((const bls::Signature*)sig)->verify(*(const bls::PublicKey*)pub);
}

