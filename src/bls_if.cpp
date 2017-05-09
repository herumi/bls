#include "bls.hpp"
#define BLS256_DLL_EXPORT
#include "bls_if.h"
#include <iostream>
#include <sstream>
#include <memory.h>

template<class Inner, class Outer>
Outer *createT()
	try
{
	return (Outer*)new Inner();
} catch (std::exception& e) {
	fprintf(stderr, "err createT %s\n", e.what());
	return NULL;
}

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
	if (ioMode == 0 || ioMode == blsIoBin || ioMode == blsIoDec || ioMode == blsIoHex) {
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

blsId *blsIdCreate()
{
	return createT<bls::Id, blsId>();
}

void blsIdDestroy(blsId *id)
{
	delete (bls::Id*)id;
}
int blsIdIsSame(const blsId *lhs, const blsId *rhs)
{
	return *(const bls::Id*)lhs == *(const bls::Id*)rhs ? 1 : 0;
}
void blsIdPut(const blsId *id)
{
	std::cout << *(const bls::Id*)id << std::endl;
}
void blsIdCopy(blsId *dst, const blsId *src)
{
	*((bls::Id*)dst) = *((const bls::Id*)src);
}

int blsIdSetStr(blsId *id, const char *buf, size_t bufSize, int ioMode)
{
	return setStrT<bls::Id, blsId>(id, buf, bufSize, ioMode);
}

size_t blsIdGetStr(const blsId *id, char *buf, size_t maxBufSize, int ioMode)
{
	return getStrT<bls::Id, blsId>(id, buf, maxBufSize, ioMode);
}

void blsIdSet(blsId *id, const uint64_t *p)
{
	((bls::Id*)id)->set(p);
}

blsSecretKey* blsSecretKeyCreate()
{
	return createT<bls::SecretKey, blsSecretKey>();
}

void blsSecretKeyDestroy(blsSecretKey *sec)
{
	delete (bls::SecretKey*)sec;
}
int blsSecretKeyIsSame(const blsSecretKey *lhs, const blsSecretKey *rhs)
{
	return *(const bls::SecretKey*)lhs == *(const bls::SecretKey*)rhs ? 1 : 0;
}
void blsSecretKeyCopy(blsSecretKey *dst, const blsSecretKey *src)
{
	*((bls::SecretKey*)dst) = *((const bls::SecretKey*)src);
}

void blsSecretKeyPut(const blsSecretKey *sec)
{
	std::cout << *(const bls::SecretKey*)sec << std::endl;
}
void blsSecretKeySetArray(blsSecretKey *sec, const uint64_t *p)
{
	((bls::SecretKey*)sec)->set(p);
}

int blsSecretKeySetStr(blsSecretKey *sec, const char *buf, size_t bufSize, int ioMode)
{
	return setStrT<bls::SecretKey, blsSecretKey>(sec, buf, bufSize, ioMode);
}
size_t blsSecretKeyGetStr(const blsSecretKey *sec, char *buf, size_t maxBufSize, int ioMode)
{
	return getStrT<bls::SecretKey, blsSecretKey>(sec, buf, maxBufSize, ioMode);
}

void blsSecretKeyInit(blsSecretKey *sec)
{
	((bls::SecretKey*)sec)->init();
}
void blsSecretKeyAdd(blsSecretKey *sec, const blsSecretKey *rhs)
{
	((bls::SecretKey*)sec)->add(*(const bls::SecretKey*)rhs);
}

void blsSecretKeyGetPublicKey(const blsSecretKey *sec, blsPublicKey *pub)
{
	((const bls::SecretKey*)sec)->getPublicKey(*(bls::PublicKey*)pub);
}
void blsSecretKeySign(const blsSecretKey *sec, blsSign *sign, const char *m, size_t size)
{
	((const bls::SecretKey*)sec)->sign(*(bls::Sign*)sign, std::string(m, size));
}
int blsSecretKeySet(blsSecretKey *sec, const blsSecretKey* msk, size_t k, const blsId *id)
	try
{
	((bls::SecretKey*)sec)->set((const bls::SecretKey *)msk, k, *(const bls::Id*)id);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsSecretKeySet %s\n", e.what());
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

void blsSecretKeyGetPop(const blsSecretKey *sec, blsSign *sign)
{
	((const bls::SecretKey*)sec)->getPop(*(bls::Sign*)sign);
}

blsPublicKey *blsPublicKeyCreate()
{
	return createT<bls::PublicKey, blsPublicKey>();
}

void blsPublicKeyDestroy(blsPublicKey *pub)
{
	delete (bls::PublicKey*)pub;
}
int blsPublicKeyIsSame(const blsPublicKey *lhs, const blsPublicKey *rhs)
{
	return *(const bls::PublicKey*)lhs == *(const bls::PublicKey*)rhs ? 1 : 0;
}
void blsPublicKeyCopy(blsPublicKey *dst, const blsPublicKey *src)
{
	*((bls::PublicKey*)dst) = *((const bls::PublicKey*)src);
}
void blsPublicKeyPut(const blsPublicKey *pub)
{
	std::cout << *(const bls::PublicKey*)pub << std::endl;
}

int blsPublicKeySetStr(blsPublicKey *pub, const char *buf, size_t bufSize, int ioMode)
{
	return setStrT<bls::PublicKey, blsPublicKey>(pub, buf, bufSize, ioMode);
}
size_t blsPublicKeyGetStr(const blsPublicKey *pub, char *buf, size_t maxBufSize, int ioMode)
{
	return getStrT<bls::PublicKey, blsPublicKey>(pub, buf, maxBufSize, ioMode);
}
void blsPublicKeyAdd(blsPublicKey *pub, const blsPublicKey *rhs)
{
	((bls::PublicKey*)pub)->add(*(const bls::PublicKey*)rhs);
}
int blsPublicKeySet(blsPublicKey *pub, const blsPublicKey *mpk, size_t k, const blsId *id)
	try
{
	((bls::PublicKey*)pub)->set((const bls::PublicKey*)mpk, k, *(const bls::Id*)id);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsPublicKeySet %s\n", e.what());
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

blsSign *blsSignCreate()
{
	return createT<bls::Sign, blsSign>();
}

void blsSignDestroy(blsSign *sign)
{
	delete (bls::Sign*)sign;
}
int blsSignIsSame(const blsSign *lhs, const blsSign *rhs)
{
	return *(const bls::Sign*)lhs == *(const bls::Sign*)rhs ? 1 : 0;
}
void blsSignCopy(blsSign *dst, const blsSign *src)
{
	*((bls::Sign*)dst) = *((const bls::Sign*)src);
}
void blsSignPut(const blsSign *sign)
{
	std::cout << *(const bls::Sign*)sign << std::endl;
}

int blsSignSetStr(blsSign *sign, const char *buf, size_t bufSize, int ioMode)
{
	return setStrT<bls::Sign, blsSign>(sign, buf, bufSize, ioMode);
}
size_t blsSignGetStr(const blsSign *sign, char *buf, size_t maxBufSize, int ioMode)
{
	return getStrT<bls::Sign, blsSign>(sign, buf, maxBufSize, ioMode);
}
void blsSignAdd(blsSign *sign, const blsSign *rhs)
{
	((bls::Sign*)sign)->add(*(const bls::Sign*)rhs);
}
int blsSignRecover(blsSign *sign, const blsSign *signVec, const blsId *idVec, size_t n)
	try
{
	((bls::Sign*)sign)->recover((const bls::Sign*)signVec, (const bls::Id*)idVec, n);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsSignRecover %s\n", e.what());
	return -1;
}

int blsSignVerify(const blsSign *sign, const blsPublicKey *pub, const char *m, size_t size)
{
	return ((const bls::Sign*)sign)->verify(*(const bls::PublicKey*)pub, std::string(m, size));
}

int blsSignVerifyPop(const blsSign *sign, const blsPublicKey *pub)
{
	return ((const bls::Sign*)sign)->verify(*(const bls::PublicKey*)pub);
}

