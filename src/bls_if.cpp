#include "bls/bls.hpp"
#define BLS_DLL_EXPORT
#include "bls/bls_if.h"
#include <iostream>
#include <sstream>
#include <memory.h>
#include <mcl/fp.hpp>

template<class Inner, class Outer>
int setStrT(Outer *p, const char *buf, size_t bufSize, int ioMode)
	try
{
	((Inner*)p)->setStr(std::string(buf, bufSize), ioMode);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err setStrT %s\n", e.what());
	return -1;
}

size_t checkAndCopy(char *buf, size_t maxBufSize, const std::string& s)
{
	if (s.size() > maxBufSize + 1) {
		return 0;
	}
	memcpy(buf, s.c_str(), s.size());
	buf[s.size()] = '\0';
	return s.size();
}
template<class Inner, class Outer>
size_t getStrT(const Outer *p, char *buf, size_t maxBufSize, int ioMode)
	try
{
	std::string s;
	((const Inner*)p)->getStr(s, ioMode);
	size_t terminate = 0;
	if (ioMode == 0 || ioMode == bls::IoBin || ioMode == bls::IoDec || ioMode == bls::IoHex) {
		terminate = 1; // for '\0'
	}
	if (s.size() > maxBufSize + terminate) {
		return 0;
	}
	memcpy(buf, s.c_str(), s.size());
	if (terminate) {
		buf[s.size()] = '\0';
	}
	return s.size();
} catch (std::exception&) {
	return 0;
}

int blsInit(int curve, int maxUnitSize)
	try
{
	bls::init(curve, maxUnitSize);
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

int blsIdIsSame(const blsId *lhs, const blsId *rhs)
{
	return *(const bls::Id*)lhs == *(const bls::Id*)rhs ? 1 : 0;
}
int blsIdSetLittleEndian(blsId *id, const void *buf, size_t bufSize)
{
	((bls::Id*)id)->setLittleEndian(buf, bufSize);
	return 0;
}
int blsIdSetDecStr(blsId *id, const char *buf, size_t bufSize)
{
	return setStrT<bls::Id, blsId>(id, buf, bufSize, 10);
}
int blsIdSetHexStr(blsId *id, const char *buf, size_t bufSize)
{
	return setStrT<bls::Id, blsId>(id, buf, bufSize, 16);
}
size_t blsIdGetLittleEndian(void *buf, size_t maxBufSize, const blsId *id)
{
	return getStrT<bls::Id, blsId>(id, (char *)buf, maxBufSize, bls::IoFixedByteSeq);
}
size_t blsIdGetDecStr(char *buf, size_t maxBufSize, const blsId *id)
{
	return getStrT<bls::Id, blsId>(id, buf, maxBufSize, 10);
}
size_t blsIdGetHexStr(char *buf, size_t maxBufSize, const blsId *id)
{
	return getStrT<bls::Id, blsId>(id, buf, maxBufSize, 16);
}
int blsSecretKeyIsSame(const blsSecretKey *lhs, const blsSecretKey *rhs)
{
	return *(const bls::SecretKey*)lhs == *(const bls::SecretKey*)rhs ? 1 : 0;
}
int blsSecretKeySetLittleEndian(blsSecretKey *sec, const void *buf, size_t bufSize)
{
	((bls::SecretKey*)sec)->setLittleEndian(buf, bufSize);
	return 0;
}
int blsSecretKeySetDecStr(blsSecretKey *sec, const char *buf, size_t bufSize)
{
	return setStrT<bls::SecretKey, blsSecretKey>(sec, buf, bufSize, 10);
}
int blsSecretKeySetHexStr(blsSecretKey *sec, const char *buf, size_t bufSize)
{
	return setStrT<bls::SecretKey, blsSecretKey>(sec, buf, bufSize, 16);
}
size_t blsSecretKeyGetLittleEndian(void *buf, size_t maxBufSize, const blsSecretKey *sec)
{
	return getStrT<bls::SecretKey, blsSecretKey>(sec, (char *)buf, maxBufSize, bls::IoFixedByteSeq);
}
size_t blsSecretKeyGetDecStr(char *buf, size_t maxBufSize, const blsSecretKey *sec)
{
	return getStrT<bls::SecretKey, blsSecretKey>(sec, buf, maxBufSize, 10);
}
size_t blsSecretKeyGetHexStr(char *buf, size_t maxBufSize, const blsSecretKey *sec)
{
	return getStrT<bls::SecretKey, blsSecretKey>(sec, buf, maxBufSize, 16);
}

int blsSecretKeySetByHash(blsSecretKey *sec, const void *buf, size_t bufSize)
	try
{
	std::string s = mcl::fp::hash(384, (const char *)buf, bufSize);
	return blsSecretKeySetLittleEndian(sec, s.c_str(), s.size());
} catch (std::exception& e) {
	fprintf(stderr, "err blsSecretKeySetByCSPRNG %s\n", e.what());
	return -1;
}

int blsSecretKeySetByCSPRNG(blsSecretKey *sec)
	try
{
	((bls::SecretKey*)sec)->init();
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsSecretKeySetByCSPRNG %s\n", e.what());
	return -1;
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

int blsPublicKeyIsSame(const blsPublicKey *lhs, const blsPublicKey *rhs)
{
	return *(const bls::PublicKey*)lhs == *(const bls::PublicKey*)rhs ? 1 : 0;
}
int blsPublicKeyDeserialize(blsPublicKey *pub, const void *buf, size_t bufSize)
{
	return setStrT<bls::PublicKey, blsPublicKey>(pub, (const char*)buf, bufSize, bls::IoFixedByteSeq);
}
size_t blsPublicKeySerialize(void *buf, size_t maxBufSize, const blsPublicKey *pub)
{
	return getStrT<bls::PublicKey, blsPublicKey>(pub, (char *)buf, maxBufSize, bls::IoFixedByteSeq);
}
int blsPublicKeySetHexStr(blsPublicKey *pub, const char *buf, size_t bufSize)
	try
{
	std::string s = mcl::fp::hexStrToLittleEndian(buf, bufSize);
	return blsPublicKeyDeserialize(pub, s.c_str(), s.size());
} catch (std::exception& e) {
	fprintf(stderr, "err blsPublicKeySetHexStr %s\n", e.what());
	return -1;
}
size_t blsPublicKeyGetHexStr(char *buf, size_t maxBufSize, const blsPublicKey *pub)
{
	std::string s;
	s.resize(1024);
	size_t len = blsPublicKeySerialize(&s[0], s.size(), pub);
	if (len > 0) {
		s.resize(len);
		s = mcl::fp::littleEndianToHexStr(s.c_str(), s.size());
		if (s.size() < maxBufSize) {
			memcpy(buf, s.c_str(), s.size());
			buf[s.size()] = '\0';
			return s.size();
		}
	}
	return 0;
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

int blsSignatureIsSame(const blsSignature *lhs, const blsSignature *rhs)
{
	return *(const bls::Signature*)lhs == *(const bls::Signature*)rhs ? 1 : 0;
}
int blsSignatureDeserialize(blsSignature *sig, const void *buf, size_t bufSize)
{
	return setStrT<bls::Signature, blsSignature>(sig, (const char *)buf, bufSize, bls::IoFixedByteSeq);
}
int blsSignatureSetHexStr(blsSignature *sig, const char *buf, size_t bufSize)
	try
{
	std::string s = mcl::fp::hexStrToLittleEndian(buf, bufSize);
	return blsSignatureDeserialize(sig, s.c_str(), s.size());
} catch (std::exception& e) {
	fprintf(stderr, "err blsSignatureSetHexStr %s\n", e.what());
	return -1;
}
size_t blsSignatureGetHexStr(char *buf, size_t maxBufSize, const blsSignature *sig)
{
	std::string s;
	s.resize(1024);
	size_t len = blsSignatureSerialize(&s[0], s.size(), sig);
	if (len > 0) {
		s.resize(len);
		s = mcl::fp::littleEndianToHexStr(s.c_str(), s.size());
		if (s.size() < maxBufSize) {
			memcpy(buf, s.c_str(), s.size());
			buf[s.size()] = '\0';
			return s.size();
		}
	}
	return 0;
}
size_t blsSignatureSerialize(void *buf, size_t maxBufSize, const blsSignature *sig)
{
	return getStrT<bls::Signature, blsSignature>(sig, (char *)buf, maxBufSize, bls::IoFixedByteSeq);
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

