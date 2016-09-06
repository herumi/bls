#include "bls.hpp"
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
int setStrT(Outer *p, const char *buf, size_t bufSize)
	try
{
	std::istringstream iss(std::string(buf, bufSize));
	iss >> *(Inner*)p;
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err setStrT %s\n", e.what());
	return 1;
}

template<class Inner, class Outer>
size_t getStrT(const Outer *p, char *buf, size_t maxBufSize)
	try
{
	std::ostringstream oss;
	oss << *(const Inner*)p;
	std::string s = oss.str();
	if (s.size() > maxBufSize) {
		fprintf(stderr, "err getStrT size is small %d %d\n", (int)s.size(), (int)maxBufSize);
		return 0;
	}
	memcpy(buf, s.c_str(), s.size());
	return s.size();
} catch (std::exception& e) {
	return 0;
}

void blsInit()
{
	bls::init();
}

blsId *blsIdCreate()
{
	return createT<bls::Id, blsId>();
}

void blsIdDestroy(blsId *id)
{
	delete (bls::Id*)id;
}

int blsIdSetStr(blsId *id, const char *buf, size_t bufSize)
{
	return setStrT<bls::Id, blsId>(id, buf, bufSize);
}

size_t blsIdGetStr(const blsId *id, char *buf, size_t maxBufSize)
{
	return getStrT<bls::Id, blsId>(id, buf, maxBufSize);
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

void blsSecretKeyPut(const blsSecretKey *sec)
{
	std::cout << *(const bls::SecretKey*)sec << std::endl;
}
void blsSecretKeySetArray(blsSecretKey *sec, const uint64_t *p)
{
	((bls::SecretKey*)sec)->set(p);
}

int blsSecretKeySetStr(blsSecretKey *sec, const char *buf, size_t bufSize)
{
	return setStrT<bls::SecretKey, blsSecretKey>(sec, buf, bufSize);
}
size_t blsSecretKeyGetStr(const blsSecretKey *sec, char *buf, size_t maxBufSize)
{
	return getStrT<bls::SecretKey, blsSecretKey>(sec, buf, maxBufSize);
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

void blsSecretKeySet(blsSecretKey *sec, const blsSecretKey* const *msk, size_t k, const blsId *id)
{
	((bls::SecretKey*)sec)->set((const bls::SecretKey *const *)msk, k, *(const bls::Id*)id);
}

void blsSecretKeyRecover(blsSecretKey *sec, const blsSecretKey* const *secVec, const blsId *const *idVec, size_t n)
{
	((bls::SecretKey*)sec)->recover((const bls::SecretKey *const *)secVec, (const bls::Id *const *)idVec, n);
}

blsPublicKey *blsPublicKeyCreate()
{
	return createT<bls::PublicKey, blsPublicKey>();
}

void blsPublicKeyDestroy(blsPublicKey *pub)
{
	delete (bls::PublicKey*)pub;
}
void blsPublicKeyPut(const blsPublicKey *pub)
{
	std::cout << *(const bls::PublicKey*)pub << std::endl;
}

int blsPublicKeySetStr(blsPublicKey *pub, const char *buf, size_t bufSize)
{
	return setStrT<bls::PublicKey, blsPublicKey>(pub, buf, bufSize);
}
size_t blsPublicKeyGetStr(const blsPublicKey *pub, char *buf, size_t maxBufSize)
{
	return getStrT<bls::PublicKey, blsPublicKey>(pub, buf, maxBufSize);
}
void blsPublicKeyAdd(blsPublicKey *pub, const blsPublicKey *rhs)
{
	((bls::PublicKey*)pub)->add(*(const bls::PublicKey*)rhs);
}
void blsPublicKeySet(blsPublicKey *pub, const blsPublicKey *const *mpk, size_t k, const blsId *id)
{
	((bls::PublicKey*)pub)->set((const bls::PublicKey* const *)mpk, k, *(const bls::Id*)id);
}
void blsPublicKeyRecover(blsPublicKey *pub, const blsPublicKey *const *pubVec, const blsId *const *idVec, size_t n)
{
	((bls::PublicKey*)pub)->recover((const bls::PublicKey* const *)pubVec, (const bls::Id* const *)idVec, n);
}

blsSign *blsSignCreate()
{
	return createT<bls::Sign, blsSign>();
}

void blsSignDestroy(blsSign *sign)
{
	delete (bls::Sign*)sign;
}
void blsSignPut(const blsSign *sign)
{
	std::cout << *(const bls::Sign*)sign << std::endl;
}

int blsSignSetStr(blsSign *sign, const char *buf, size_t bufSize)
{
	return setStrT<bls::Sign, blsSign>(sign, buf, bufSize);
}
size_t blsSignGetStr(const blsSign *sign, char *buf, size_t maxBufSize)
{
	return getStrT<bls::Sign, blsSign>(sign, buf, maxBufSize);
}
void blsSignAdd(blsSign *sign, const blsSign *rhs)
{
	((bls::Sign*)sign)->add(*(const bls::Sign*)rhs);
}
void blsSignRecover(blsSign *sign, const blsSign *const *signVec, const blsId *const *idVec, size_t n)
{
	((bls::Sign*)sign)->recover((const bls::Sign* const *)signVec, (const bls::Id* const *)idVec, n);
}

int blsSignVerify(const blsSign *sign, const blsPublicKey *pub, const char *m, size_t size)
{
	return ((const bls::Sign*)sign)->verify(*(const bls::PublicKey*)pub, std::string(m, size));
}

