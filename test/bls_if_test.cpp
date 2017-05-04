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
	n = blsSecretKeyGetStr(&sec1, buf, sizeof(buf), BlsIoEcComp);
	CYBOZU_TEST_EQUAL(n, fpSize);
	ret = blsSecretKeySetStr(&sec2, buf, n, BlsIoEcComp);
	CYBOZU_TEST_EQUAL(ret, 0);
	CYBOZU_TEST_ASSERT(blsSecretKeyIsSame(&sec1, &sec2));
	blsPublicKey pub1, pub2;
	blsSecretKeyGetPublicKey(&sec1, &pub1);
	n = blsPublicKeyGetStr(&pub1, buf, sizeof(buf), BlsIoEcComp);
	CYBOZU_TEST_EQUAL(n, fpSize * 2);
	ret = blsPublicKeySetStr(&pub2, buf, n, BlsIoEcComp);
	CYBOZU_TEST_EQUAL(ret, 0);
	CYBOZU_TEST_ASSERT(blsPublicKeyIsSame(&pub1, &pub2));
	blsSign sign1, sign2;
	blsSecretKeySign(&sec1, &sign1, msg, msgSize);
	n = blsSignGetStr(&sign1, buf, sizeof(buf), BlsIoEcComp);
	CYBOZU_TEST_EQUAL(n, fpSize);
	ret = blsSignSetStr(&sign2, buf, n, BlsIoEcComp);
	CYBOZU_TEST_EQUAL(ret, 0);
	CYBOZU_TEST_ASSERT(blsSignIsSame(&sign1, &sign2));
}

void bls_ifOrderTest(const char *curveOrder, const char *fieldOrder)
{
	char buf[1024];
	size_t len;
	len = blsGetCurveOrder(buf, sizeof(buf));
	CYBOZU_TEST_ASSERT(len > 0);
	CYBOZU_TEST_EQUAL(buf, curveOrder);
	len = blsGetFieldOrder(buf, sizeof(buf));
	CYBOZU_TEST_ASSERT(len > 0);
	CYBOZU_TEST_EQUAL(buf, fieldOrder);
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
	const char *curveOrderTbl[] = {
		"16798108731015832284940804142231733909759579603404752749028378864165570215949",
		"5540996953667913971058039301942914304734176495422447785042938606876043190415948413757785063597439175372845535461389",
		"5541245505022739011583672869577435255026888277144126952448297309161979278754528049907713682488818304329661351460877",
	};
	const char *fieldOrderTbl[] = {
		"16798108731015832284940804142231733909889187121439069848933715426072753864723",
		"5540996953667913971058039301942914304734176495422447785045292539108217242186829586959562222833658991069414454984723",
		"5541245505022739011583672869577435255026888277144126952450651294188487038640194767986566260919128250811286032482323",
	};
	for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
		printf("i=%d\n", (int)i);
		blsInit(tbl[i], BLS_MAX_OP_UNIT_SIZE);
		bls_ifTest();
		bls_if_use_stackTest();
		bls_ifDataTest();
		bls_ifOrderTest(curveOrderTbl[i], fieldOrderTbl[i]);
	}
}
