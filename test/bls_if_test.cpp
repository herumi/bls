#include <cybozu/test.hpp>
#include <bls_if.h>
#include <string.h>

CYBOZU_TEST_AUTO(bls_if)
{
	blsSecretKey *sec;
	blsPublicKey *pub;
	blsSign *sign;
	const char *msg = "this is a pen";
	const size_t msgSize = strlen(msg);

	blsInit();
	sec = blsSecretKeyCreate();
	blsSecretKeyInit(sec);
	blsSecretKeyPut(sec);

	pub = blsPublicKeyCreate();
	blsSecretKeyGetPublicKey(sec, pub);
	blsPublicKeyPut(pub);

	sign = blsSignCreate();
	blsSecretKeySign(sec, sign, msg, msgSize);
	blsSignPut(sign);

	printf("verify %d\n", blsSignVerify(sign, pub, msg, msgSize));

	blsSignDestroy(sign);
	blsPublicKeyDestroy(pub);
	blsSecretKeyDestroy(sec);
}

CYBOZU_TEST_AUTO(bls_if_use_stack)
{
	blsSecretKey sec;
	blsPublicKey pub;
	blsSign sign;
	const char *msg = "this is a pen";
	const size_t msgSize = strlen(msg);

	blsInit();
	blsSecretKeyInit(&sec);
	blsSecretKeyPut(&sec);

	blsSecretKeyGetPublicKey(&sec, &pub);
	blsPublicKeyPut(&pub);

	blsSecretKeySign(&sec, &sign, msg, msgSize);
	blsSignPut(&sign);

	printf("verify %d\n", blsSignVerify(&sign, &pub, msg, msgSize));
}
