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

	blsInit(BlsCurveFp254BNb, BLS_MAX_OP_UNIT_SIZE);
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

	blsInit(BlsCurveFp254BNb, BLS_MAX_OP_UNIT_SIZE);
	blsSecretKeyInit(&sec);
	blsSecretKeyPut(&sec);

	blsSecretKeyGetPublicKey(&sec, &pub);
	blsPublicKeyPut(&pub);

	blsSecretKeySign(&sec, &sign, msg, msgSize);
	blsSignPut(&sign);

	printf("verify %d\n", blsSignVerify(&sign, &pub, msg, msgSize));
}
