#include <cybozu/test.hpp>
#include <cybozu/inttype.hpp>
#include <bls/bls.h>
#include <string.h>
#include <cybozu/benchmark.hpp>

void bls_use_stackTest()
{
	blsSecretKey sec;
	blsPublicKey pub;
	blsSignature sig;
	const char *msg = "this is a pen";
	const size_t msgSize = strlen(msg);

	blsSecretKeySetByCSPRNG(&sec);

	blsGetPublicKey(&pub, &sec);

	blsSign(&sig, &sec, msg, msgSize);

	CYBOZU_TEST_ASSERT(blsVerify(&sig, &pub, msg, msgSize));
}

void blsDataTest()
{
	const char *msg = "test test";
	const size_t msgSize = strlen(msg);
	const size_t FrSize = blsGetFrByteSize();
	const size_t FpSize = blsGetG1ByteSize();
	blsSecretKey sec1, sec2;
	blsSecretKeySetByCSPRNG(&sec1);
	char buf[1024];
	size_t n;
	size_t ret;
	n = blsSecretKeyGetHexStr(buf, sizeof(buf), &sec1);
	CYBOZU_TEST_ASSERT(0 < n && n <= FrSize * 2);
	ret = blsSecretKeySetHexStr(&sec2, buf, n);
	CYBOZU_TEST_EQUAL(ret, 0);
	CYBOZU_TEST_ASSERT(blsSecretKeyIsEqual(&sec1, &sec2));

	memset(&sec2, 0, sizeof(sec2));
	n = blsSecretKeySerialize(buf, sizeof(buf), &sec1);
	CYBOZU_TEST_EQUAL(n, FrSize);
	ret = blsSecretKeyDeserialize(&sec2, buf, n);
	CYBOZU_TEST_EQUAL(ret, n);
	CYBOZU_TEST_ASSERT(blsSecretKeyIsEqual(&sec1, &sec2));

	blsPublicKey pub1, pub2;
	blsGetPublicKey(&pub1, &sec1);
	n = blsPublicKeySerialize(buf, sizeof(buf), &pub1);
	CYBOZU_TEST_EQUAL(n, FpSize * 2);
	ret = blsPublicKeyDeserialize(&pub2, buf, n);
	CYBOZU_TEST_EQUAL(ret, n);
	CYBOZU_TEST_ASSERT(blsPublicKeyIsEqual(&pub1, &pub2));
	blsSignature sig1, sig2;
	blsSign(&sig1, &sec1, msg, msgSize);
	n = blsSignatureSerialize(buf, sizeof(buf), &sig1);
	CYBOZU_TEST_EQUAL(n, FpSize);
	ret = blsSignatureDeserialize(&sig2, buf, n);
	CYBOZU_TEST_EQUAL(ret, n);
	CYBOZU_TEST_ASSERT(blsSignatureIsEqual(&sig1, &sig2));
}

void blsOrderTest(const char *curveOrder, const char *fieldOrder)
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

#if !defined(DISABLE_THREAD_TEST) || defined(__clang__)
#if defined(CYBOZU_CPP_VERSION) && CYBOZU_CPP_VERSION >= CYBOZU_CPP_VERSION_CPP11
#include <thread>
#include <vector>
struct Thread {
	std::unique_ptr<std::thread> t;
	Thread() : t() {}
	~Thread()
	{
		if (t) {
			t->join();
		}
	}
	template<class F>
	void run(F func, int p1, int p2)
	{
		t.reset(new std::thread(func, p1, p2));
	}
};

CYBOZU_TEST_AUTO(multipleInit)
{
	const size_t n = 100;
	{
		std::vector<Thread> vt(n);
		for (size_t i = 0; i < n; i++) {
			vt[i].run(blsInit, MCL_BN254, MCLBN_COMPILED_TIME_VAR);
		}
	}
	CYBOZU_TEST_EQUAL(blsGetOpUnitSize(), 4u);
#if MCLBN_FP_UNIT_SIZE == 6
	{
		std::vector<Thread> vt(n);
		for (size_t i = 0; i < n; i++) {
			vt[i].run(blsInit, MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
		}
	}
	CYBOZU_TEST_EQUAL(blsGetOpUnitSize(), 6u);
#endif
}
#endif
#endif

void blsSerializeTest()
{
	const size_t FrSize = blsGetFrByteSize();
	const size_t FpSize = blsGetG1ByteSize();
	printf("FrSize=%d, FpSize=%d\n", (int)FrSize, (int)FpSize);
	blsId id1, id2;
	blsSecretKey sec1, sec2;
	blsPublicKey pub1, pub2;
	blsSignature sig1, sig2;
	char buf[1024];
	size_t n;
	size_t expectSize;
	size_t ret;
	const char dummyChar = '1';

	// Id
	expectSize = FrSize;
	blsIdSetInt(&id1, -1);
	n = blsIdSerialize(buf, sizeof(buf), &id1);
	CYBOZU_TEST_EQUAL(n, expectSize);

	ret = blsIdDeserialize(&id2, buf, n);
	CYBOZU_TEST_EQUAL(ret, n);
	CYBOZU_TEST_ASSERT(blsIdIsEqual(&id1, &id2));

	ret = blsIdDeserialize(&id2, buf, n - 1);
	CYBOZU_TEST_EQUAL(ret, 0);

	memset(&id2, 0, sizeof(id2));
	buf[n] = dummyChar;
	ret = blsIdDeserialize(&id2, buf, n + 1);
	CYBOZU_TEST_EQUAL(ret, n);
	CYBOZU_TEST_ASSERT(blsIdIsEqual(&id1, &id2));

	n = blsIdSerialize(buf, expectSize, &id1);
	CYBOZU_TEST_EQUAL(n, expectSize);

	// SecretKey
	expectSize = FrSize;
	blsSecretKeySetDecStr(&sec1, "-1", 2);
	n = blsSecretKeySerialize(buf, sizeof(buf), &sec1);
	CYBOZU_TEST_EQUAL(n, expectSize);

	ret = blsSecretKeyDeserialize(&sec2, buf, n);
	CYBOZU_TEST_EQUAL(ret, n);
	CYBOZU_TEST_ASSERT(blsSecretKeyIsEqual(&sec1, &sec2));

	ret = blsSecretKeyDeserialize(&sec2, buf, n - 1);
	CYBOZU_TEST_EQUAL(ret, 0);

	memset(&sec2, 0, sizeof(sec2));
	buf[n] = dummyChar;
	ret = blsSecretKeyDeserialize(&sec2, buf, n + 1);
	CYBOZU_TEST_EQUAL(ret, n);
	CYBOZU_TEST_ASSERT(blsSecretKeyIsEqual(&sec1, &sec2));

	n = blsSecretKeySerialize(buf, expectSize, &sec1);
	CYBOZU_TEST_EQUAL(n, expectSize);

	// PublicKey
	expectSize = FpSize * 2;
	blsGetPublicKey(&pub1, &sec1);
	n = blsPublicKeySerialize(buf, sizeof(buf), &pub1);
	CYBOZU_TEST_EQUAL(n, expectSize);
	CYBOZU_TEST_ASSERT(blsPublicKeyIsValidOrder(&pub1));

	ret = blsPublicKeyDeserialize(&pub2, buf, n);
	CYBOZU_TEST_EQUAL(ret, n);
	CYBOZU_TEST_ASSERT(blsPublicKeyIsEqual(&pub1, &pub2));

	ret = blsPublicKeyDeserialize(&pub2, buf, n - 1);
	CYBOZU_TEST_EQUAL(ret, 0);

	memset(&pub2, 0, sizeof(pub2));
	buf[n] = dummyChar;
	ret = blsPublicKeyDeserialize(&pub2, buf, n + 1);
	CYBOZU_TEST_EQUAL(ret, n);
	CYBOZU_TEST_ASSERT(blsPublicKeyIsEqual(&pub1, &pub2));

	n = blsPublicKeySerialize(buf, expectSize, &pub1);
	CYBOZU_TEST_EQUAL(n, expectSize);

	// Signature
	expectSize = FpSize;
	blsSign(&sig1, &sec1, "abc", 3);
	n = blsSignatureSerialize(buf, sizeof(buf), &sig1);
	CYBOZU_TEST_EQUAL(n, expectSize);
	CYBOZU_TEST_ASSERT(blsSignatureIsValidOrder(&sig1));

	ret = blsSignatureDeserialize(&sig2, buf, n);
	CYBOZU_TEST_EQUAL(ret, n);
	CYBOZU_TEST_ASSERT(blsSignatureIsEqual(&sig1, &sig2));

	ret = blsSignatureDeserialize(&sig2, buf, n - 1);
	CYBOZU_TEST_EQUAL(ret, 0);

	memset(&sig2, 0, sizeof(sig2));
	buf[n] = dummyChar;
	ret = blsSignatureDeserialize(&sig2, buf, n + 1);
	CYBOZU_TEST_EQUAL(ret, n);
	CYBOZU_TEST_ASSERT(blsSignatureIsEqual(&sig1, &sig2));

	n = blsSignatureSerialize(buf, expectSize, &sig1);
	CYBOZU_TEST_EQUAL(n, expectSize);
}

void blsVerifyOrderTest()
{
	puts("blsVerifyOrderTest");
	const uint8_t Ps[] = {
0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
	};
	const uint8_t Qs[] = {
0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
	};
	size_t n;
	blsPublicKey pub;
	n = blsPublicKeyDeserialize(&pub, Ps, sizeof(Ps));
	CYBOZU_TEST_EQUAL(n, 0);
	blsPublicKeyVerifyOrder(0);
	n = blsPublicKeyDeserialize(&pub, Ps, sizeof(Ps));
	CYBOZU_TEST_ASSERT(n > 0);
	CYBOZU_TEST_ASSERT(!blsPublicKeyIsValidOrder(&pub));
	blsPublicKeyVerifyOrder(1);

	blsSignature sig;
	n = blsSignatureDeserialize(&sig, Qs, sizeof(Ps));
	CYBOZU_TEST_EQUAL(n, 0);
	blsSignatureVerifyOrder(0);
	n = blsSignatureDeserialize(&sig, Qs, sizeof(Ps));
	CYBOZU_TEST_ASSERT(n > 0);
	CYBOZU_TEST_ASSERT(!blsSignatureIsValidOrder(&sig));
	blsSignatureVerifyOrder(1);
}

void blsAddSubTest()
{
	blsSecretKey sec[3];
	blsPublicKey pub[3];
	blsSignature sig[3];
	const char *msg = "this is a pen";
	const size_t msgSize = strlen(msg);

	const char *secHexStr[8] = { "12", "34" };
	for (int i = 0; i < 2; i++) {
		blsSecretKeySetHexStr(&sec[i], secHexStr[i], strlen(secHexStr[i]));
		blsGetPublicKey(&pub[i], &sec[i]);
		blsSign(&sig[i], &sec[i], msg, msgSize);
	}
	sec[2] = sec[0];
	blsSecretKeyAdd(&sec[2], &sec[1]);
	char buf[1024];
	size_t n = blsSecretKeyGetHexStr(buf, sizeof(buf), &sec[2]);
	CYBOZU_TEST_EQUAL(n, 2);
	CYBOZU_TEST_EQUAL(buf, "46"); // "12" + "34"

	pub[2] = pub[0];
	blsPublicKeyAdd(&pub[2], &pub[1]);
	sig[2] = sig[0];
	blsSignatureAdd(&sig[2], &sig[1]); // sig[2] = sig[0] + sig[1]
	blsSignature sig2;
	blsSign(&sig2, &sec[2], msg, msgSize); // sig2 = signature by sec[2]
	CYBOZU_TEST_ASSERT(blsSignatureIsEqual(&sig2, &sig[2]));
	CYBOZU_TEST_ASSERT(blsVerify(&sig[2], &pub[2], msg, msgSize)); // verify by pub[2]

	blsSecretKeySub(&sec[2], &sec[1]);
	CYBOZU_TEST_ASSERT(blsSecretKeyIsEqual(&sec[2], &sec[0]));
	blsPublicKeySub(&pub[2], &pub[1]);
	CYBOZU_TEST_ASSERT(blsPublicKeyIsEqual(&pub[2], &pub[0]));
	blsSignatureSub(&sig[2], &sig[1]);
	CYBOZU_TEST_ASSERT(blsSignatureIsEqual(&sig[2], &sig[0]));
}

void blsBench()
{
	blsSecretKey sec;
	blsPublicKey pub;
	blsSignature sig;
	const char *msg = "this is a pen";
	const size_t msgSize = strlen(msg);

	blsSecretKeySetByCSPRNG(&sec);

	blsGetPublicKey(&pub, &sec);

	CYBOZU_BENCH_C("sign", 1000, blsSign, &sig, &sec, msg, msgSize);
	CYBOZU_BENCH_C("verify", 1000, blsVerify, &sig, &pub, msg, msgSize);
}

CYBOZU_TEST_AUTO(all)
{
	const int tbl[] = {
		MCL_BN254,
#if MCLBN_FP_UNIT_SIZE == 6
		MCL_BN381_1,
		MCL_BLS12_381,
#endif
	};
	const char *curveOrderTbl[] = {
		"16798108731015832284940804142231733909759579603404752749028378864165570215949",
		"5540996953667913971058039301942914304734176495422447785042938606876043190415948413757785063597439175372845535461389",
		"52435875175126190479447740508185965837690552500527637822603658699938581184513",
	};
	const char *fieldOrderTbl[] = {
		"16798108731015832284940804142231733909889187121439069848933715426072753864723",
		"5540996953667913971058039301942914304734176495422447785045292539108217242186829586959562222833658991069414454984723",
		"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787",
	};
	for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
		printf("i=%d\n", (int)i);
		blsInit(tbl[i], MCLBN_COMPILED_TIME_VAR);
		bls_use_stackTest();
		blsDataTest();
		blsOrderTest(curveOrderTbl[i], fieldOrderTbl[i]);
		blsSerializeTest();
		if (tbl[i] == MCL_BLS12_381) blsVerifyOrderTest();
		blsAddSubTest();
		blsBench();
	}
}
