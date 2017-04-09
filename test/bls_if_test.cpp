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

void bls_ifDataTest()
{
	const char *msg = "test test";
	const size_t msgSize = strlen(msg);
	const size_t fpSize = blsGetOpUnitSize() * sizeof(uint64_t);
	blsSecretKey sec1, sec2;
	blsSecretKeyInit(&sec1);
	char buf[BLS_MAX_OP_UNIT_SIZE * sizeof(uint64_t) * 2];
	size_t n;
	int ret;
	n = blsSecretKeyGetData(&sec1, buf, sizeof(buf));
	CYBOZU_TEST_EQUAL(n, fpSize);
	ret = blsSecretKeySetData(&sec2, buf, n);
	CYBOZU_TEST_EQUAL(ret, 0);
	CYBOZU_TEST_ASSERT(blsSecretKeyIsSame(&sec1, &sec2));
	blsPublicKey pub1, pub2;
	blsSecretKeyGetPublicKey(&sec1, &pub1);
	n = blsPublicKeyGetData(&pub1, buf, sizeof(buf));
	CYBOZU_TEST_EQUAL(n, fpSize * 2);
	ret = blsPublicKeySetData(&pub2, buf, n);
	CYBOZU_TEST_EQUAL(ret, 0);
	CYBOZU_TEST_ASSERT(blsPublicKeyIsSame(&pub1, &pub2));
	blsSign sign1, sign2;
	blsSecretKeySign(&sec1, &sign1, msg, msgSize);
	n = blsSignGetData(&sign1, buf, sizeof(buf));
	CYBOZU_TEST_EQUAL(n, fpSize);
	ret = blsSignSetData(&sign2, buf, n);
	CYBOZU_TEST_EQUAL(ret, 0);
	CYBOZU_TEST_ASSERT(blsSignIsSame(&sign1, &sign2));
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
		bls_ifDataTest();
	}
}
