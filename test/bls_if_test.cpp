#include <cybozu/test.hpp>
#include <bls_if.h>
#include <string.h>

void bls_ifTest()
{
	blsSecretKey *sec;
	blsPublicKey *pub;
	blsSign *sign;
	const char *msg = "this is a pen";
	const size_t msgSize = strlen(msg);

	sec = blsSecretKeyCreate();
	blsSecretKeyInit(sec);
	blsSecretKeyPut(sec);

	pub = blsPublicKeyCreate();
	blsSecretKeyGetPublicKey(sec, pub);
	blsPublicKeyPut(pub);

	sign = blsSignCreate();
	blsSecretKeySign(sec, sign, msg, msgSize);
	blsSignPut(sign);

	CYBOZU_TEST_ASSERT(blsSignVerify(sign, pub, msg, msgSize));

	blsSignDestroy(sign);
	blsPublicKeyDestroy(pub);
	blsSecretKeyDestroy(sec);
}

void bls_if_use_stackTest()
{
	blsSecretKey sec;
	blsPublicKey pub;
	blsSign sign;
	const char *msg = "this is a pen";
	const size_t msgSize = strlen(msg);

	blsSecretKeyInit(&sec);
	blsSecretKeyPut(&sec);

	blsSecretKeyGetPublicKey(&sec, &pub);
	blsPublicKeyPut(&pub);

	blsSecretKeySign(&sec, &sign, msg, msgSize);
	blsSignPut(&sign);

	CYBOZU_TEST_ASSERT(blsSignVerify(&sign, &pub, msg, msgSize));
}

CYBOZU_TEST_AUTO(all)
{
	const int tbl[] = {
		BlsCurveFp254BNb,
#if BLS_MAX_OP_UNIT_SIZE == 6
		BlsCurveFp382_1,
		BlsCurveFp382_2
#endif
	};
	for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
		printf("i=%d\n", (int)i);
		blsInit(tbl[i], BLS_MAX_OP_UNIT_SIZE);
		bls_ifTest();
		bls_if_use_stackTest();
	}
}
