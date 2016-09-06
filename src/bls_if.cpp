#include "bls.hpp"
#include "bls_if.h"
#include <iostream>

void blsInit(void)
{
	bls::init();
}

blsId *blsIdCreate(void)
	try
{
	return (blsId*)new bls::Id();
} catch (std::exception& e) {
	fprintf(stderr, "err %s\n", e.what());
	return NULL;
}

void blsIdDestroy(blsId *id)
{
	delete (bls::Id*)id;
}

void blsIdPut(const blsId *id)
{
	std::cout << *(const bls::Id*)id << std::endl;
}

void blsIdSet(blsId *id, const uint64_t *p)
{
	((bls::Id*)id)->set(p);
}

blsSecretKey* blsSecretKeyCreate(void)
	try
{
	return (blsSecretKey*)new bls::SecretKey();
} catch (std::exception& e) {
	fprintf(stderr, "err %s\n", e.what());
	return NULL;
}

void blsSecretKeyDestroy(blsSecretKey *sec)
{
	delete (bls::SecretKey*)sec;
}

void blsSecretKeyPut(const blsSecretKey *sec)
{
	std::cout << *(const bls::SecretKey*)sec << std::endl;
}

void blsSecretKeyInit(blsSecretKey *sec)
{
	((bls::SecretKey*)sec)->init();
}

void blsSecretKeyGetPublicKey(const blsSecretKey *sec, blsPublicKey *pub)
{
	((const bls::SecretKey*)sec)->getPublicKey(*(bls::PublicKey*)pub);
}
void blsSecretKeySign(const blsSecretKey *sec, blsSign *sign, const char *m, size_t size)
{
	((const bls::SecretKey*)sec)->sign(*(bls::Sign*)sign, std::string(m, size));
}

blsPublicKey *blsPublicKeyCreate(void)
	try
{
	return (blsPublicKey*)new bls::PublicKey();
} catch (std::exception& e) {
	fprintf(stderr, "err %s\n", e.what());
	return NULL;
}
void blsPublicKeyDestroy(blsPublicKey *pub)
{
	delete (bls::PublicKey*)pub;
}
void blsPublicKeyPut(const blsPublicKey *pub)
{
	std::cout << *(const bls::PublicKey*)pub << std::endl;
}

blsSign *blsSignCreate(void)
	try
{
	return (blsSign*)new bls::Sign();
} catch (std::exception& e) {
	fprintf(stderr, "err %s\n", e.what());
	return NULL;
}
void blsSignDestroy(blsSign *sign)
{
	delete (bls::Sign*)sign;
}
void blsSignPut(const blsSign *sign)
{
	std::cout << *(const bls::Sign*)sign << std::endl;
}

int blsSignVerify(const blsSign *sign, const blsPublicKey *pub, const char *m, size_t size)
{
	return ((const bls::Sign*)sign)->verify(*(const bls::PublicKey*)pub, std::string(m, size));
}

