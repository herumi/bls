#include <bls.hpp>
#include <cybozu/test.hpp>
#include <cybozu/inttype.hpp>
#include <iostream>
#include <sstream>
#include <cybozu/benchmark.hpp>

template<class T>
void streamTest(const T& t)
{
	std::ostringstream oss;
	oss << t;
	std::istringstream iss(oss.str());
	T t2;
	iss >> t2;
	CYBOZU_TEST_EQUAL(t, t2);
}

template<class T>
void testSet()
{
	/*
		mask value to be less than r if the value >= (1 << (192 + 62))
	*/
	const uint64_t fff = uint64_t(-1);
	const uint64_t one = uint64_t(1);
	const struct {
		uint64_t in;
		uint64_t expected;
	} tbl[] = {
		{ fff, (one << 61) - 1 }, // masked with (1 << 61) - 1
		{ one << 62, 0 }, // masked
		{ (one << 62) | (one << 61), (one << 61) }, // masked
		{ (one << 61) - 1, (one << 61) - 1 }, // same
	};
	T t1, t2;
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		uint64_t v1[] = { fff, fff, fff, tbl[i].in };
		uint64_t v2[] = { fff, fff, fff, tbl[i].expected };
		t1.set(v1);
		t2.set(v2);
		CYBOZU_TEST_EQUAL(t1, t2);
	}
}

void IdTestBN256()
{
	bls::Id id;
	CYBOZU_TEST_ASSERT(id.isZero());
	id = 5;
	CYBOZU_TEST_EQUAL(id, 5);
	{
		const uint64_t id1[] = { 1, 2, 3, 4 };
		id.set(id1);
		std::ostringstream os;
		os << id;
		CYBOZU_TEST_EQUAL(os.str(), "0x4000000000000000300000000000000020000000000000001");
	}
	testSet<bls::Id>();
}

void SecretKeyTestBN256()
{
	testSet<bls::SecretKey>();
}

CYBOZU_TEST_AUTO(bn256)
{
	bls::init(bls::CurveFp254BNb);
	IdTestBN256();
	SecretKeyTestBN256();
	CYBOZU_TEST_EQUAL(bls::getOpUnitSize(), 4);
}

void blsTest()
{
	bls::SecretKey sec;
	sec.init();
	streamTest(sec);
	bls::PublicKey pub;
	sec.getPublicKey(pub);
	streamTest(pub);
	for (int i = 0; i < 5; i++) {
		std::string m = "hello";
		m += char('0' + i);
		bls::Sign s;
		sec.sign(s, m);
		CYBOZU_TEST_ASSERT(s.verify(pub, m));
		CYBOZU_TEST_ASSERT(!s.verify(pub, m + "a"));
		streamTest(s);
		CYBOZU_BENCH_C("sign", 100, sec.sign, s, m);
		CYBOZU_BENCH_C("verify", 100, s.verify, pub, m);
	}
}

void k_of_nTest()
{
	const std::string m = "abc";
	const int n = 5;
	const int k = 3;
	bls::SecretKey sec0;
	sec0.init();
	bls::Sign s0;
	sec0.sign(s0, m);
	bls::PublicKey pub0;
	sec0.getPublicKey(pub0);
	CYBOZU_TEST_ASSERT(s0.verify(pub0, m));

	bls::SecretKeyVec msk;
	sec0.getMasterSecretKey(msk, k);

	bls::SecretKeyVec allPrvVec(n);
	bls::IdVec allIdVec(n);
	for (int i = 0; i < n; i++) {
		int id = i + 1;
		allPrvVec[i].set(msk, id);
		allIdVec[i] = id;

		bls::SecretKey p;
		p.set(msk.data(), k, id);
		CYBOZU_TEST_EQUAL(allPrvVec[i], p);
	}

	bls::SignVec allSignVec(n);
	for (int i = 0; i < n; i++) {
		CYBOZU_TEST_ASSERT(allPrvVec[i] != sec0);
		allPrvVec[i].sign(allSignVec[i], m);
		bls::PublicKey pub;
		allPrvVec[i].getPublicKey(pub);
		CYBOZU_TEST_ASSERT(pub != pub0);
		CYBOZU_TEST_ASSERT(allSignVec[i].verify(pub, m));
	}

	/*
		3-out-of-n
		can recover
	*/
	bls::SecretKeyVec secVec(3);
	bls::IdVec idVec(3);
	for (int a = 0; a < n; a++) {
		secVec[0] = allPrvVec[a];
		idVec[0] = allIdVec[a];
		for (int b = a + 1; b < n; b++) {
			secVec[1] = allPrvVec[b];
			idVec[1] = allIdVec[b];
			for (int c = b + 1; c < n; c++) {
				secVec[2] = allPrvVec[c];
				idVec[2] = allIdVec[c];
				bls::SecretKey sec;
				sec.recover(secVec, idVec);
				CYBOZU_TEST_EQUAL(sec, sec0);
				bls::SecretKey sec2;
				sec2.recover(secVec.data(), idVec.data(), secVec.size());
				CYBOZU_TEST_EQUAL(sec, sec2);
			}
		}
	}
	{
		secVec[0] = allPrvVec[0];
		secVec[1] = allPrvVec[1];
		secVec[2] = allPrvVec[0]; // same of secVec[0]
		idVec[0] = allIdVec[0];
		idVec[1] = allIdVec[1];
		idVec[2] = allIdVec[0];
		bls::SecretKey sec;
		CYBOZU_TEST_EXCEPTION_MESSAGE(sec.recover(secVec, idVec), std::exception, "same id");
	}
	{
		/*
			n-out-of-n
			can recover
		*/
		bls::SecretKey sec;
		sec.recover(allPrvVec, allIdVec);
		CYBOZU_TEST_EQUAL(sec, sec0);
	}
	/*
		2-out-of-n
		can't recover
	*/
	secVec.resize(2);
	idVec.resize(2);
	for (int a = 0; a < n; a++) {
		secVec[0] = allPrvVec[a];
		idVec[0] = allIdVec[a];
		for (int b = a + 1; b < n; b++) {
			secVec[1] = allPrvVec[b];
			idVec[1] = allIdVec[b];
			bls::SecretKey sec;
			sec.recover(secVec, idVec);
			CYBOZU_TEST_ASSERT(sec != sec0);
		}
	}
	/*
		3-out-of-n
		can recover
	*/
	bls::SignVec signVec(3);
	idVec.resize(3);
	for (int a = 0; a < n; a++) {
		signVec[0] = allSignVec[a];
		idVec[0] = allIdVec[a];
		for (int b = a + 1; b < n; b++) {
			signVec[1] = allSignVec[b];
			idVec[1] = allIdVec[b];
			for (int c = b + 1; c < n; c++) {
				signVec[2] = allSignVec[c];
				idVec[2] = allIdVec[c];
				bls::Sign s;
				s.recover(signVec, idVec);
				CYBOZU_TEST_EQUAL(s, s0);
			}
		}
	}
	{
		signVec[0] = allSignVec[1]; idVec[0] = allIdVec[1];
		signVec[1] = allSignVec[4]; idVec[1] = allIdVec[4];
		signVec[2] = allSignVec[3]; idVec[2] = allIdVec[3];
		bls::Sign s;
		CYBOZU_BENCH_C("s.recover", 100, s.recover, signVec, idVec);
	}
	{
		/*
			n-out-of-n
			can recover
		*/
		bls::Sign s;
		s.recover(allSignVec, allIdVec);
		CYBOZU_TEST_EQUAL(s, s0);
	}
	/*
		2-out-of-n
		can't recover
	*/
	signVec.resize(2);
	idVec.resize(2);
	for (int a = 0; a < n; a++) {
		signVec[0] = allSignVec[a];
		idVec[0] = allIdVec[a];
		for (int b = a + 1; b < n; b++) {
			signVec[1] = allSignVec[b];
			idVec[1] = allIdVec[b];
			bls::Sign s;
			s.recover(signVec, idVec);
			CYBOZU_TEST_ASSERT(s != s0);
		}
	}
	// share and recover publicKey
	{
		bls::PublicKeyVec pubVec(k);
		idVec.resize(k);
		// select [0, k) publicKey
		for (int i = 0; i < k; i++) {
			allPrvVec[i].getPublicKey(pubVec[i]);
			idVec[i] = allIdVec[i];
		}
		bls::PublicKey pub;
		pub.recover(pubVec, idVec);
		CYBOZU_TEST_EQUAL(pub, pub0);
		bls::PublicKey pub2;
		pub2.recover(pubVec.data(), idVec.data(), pubVec.size());
		CYBOZU_TEST_EQUAL(pub, pub2);
	}
}

void popTest()
{
	const size_t k = 3;
	const size_t n = 6;
	const std::string m = "pop test";
	bls::SecretKey sec0;
	sec0.init();
	bls::PublicKey pub0;
	sec0.getPublicKey(pub0);
	bls::Sign s0;
	sec0.sign(s0, m);
	CYBOZU_TEST_ASSERT(s0.verify(pub0, m));

	bls::SecretKeyVec msk;
	sec0.getMasterSecretKey(msk, k);

	bls::PublicKeyVec mpk;
	bls::getMasterPublicKey(mpk, msk);
	bls::SignVec  popVec;
	bls::getPopVec(popVec, msk);

	for (size_t i = 0; i < popVec.size(); i++) {
		CYBOZU_TEST_ASSERT(popVec[i].verify(mpk[i]));
	}

	const int idTbl[n] = {
		3, 5, 193, 22, 15
	};
	bls::SecretKeyVec secVec(n);
	bls::PublicKeyVec pubVec(n);
	bls::SignVec sVec(n);
	for (size_t i = 0; i < n; i++) {
		int id = idTbl[i];
		secVec[i].set(msk, id);
		secVec[i].getPublicKey(pubVec[i]);
		bls::PublicKey pub;
		pub.set(mpk, id);
		CYBOZU_TEST_EQUAL(pubVec[i], pub);

		bls::Sign pop;
		secVec[i].getPop(pop);
		CYBOZU_TEST_ASSERT(pop.verify(pubVec[i]));

		secVec[i].sign(sVec[i], m);
		CYBOZU_TEST_ASSERT(sVec[i].verify(pubVec[i], m));
	}
	secVec.resize(k);
	sVec.resize(k);
	bls::IdVec idVec(k);
	for (size_t i = 0; i < k; i++) {
		idVec[i] = idTbl[i];
	}
	bls::SecretKey sec;
	sec.recover(secVec, idVec);
	CYBOZU_TEST_EQUAL(sec, sec0);
	bls::Sign s;
	s.recover(sVec, idVec);
	CYBOZU_TEST_EQUAL(s, s0);
	bls::Sign s2;
	s2.recover(sVec.data(), idVec.data(), sVec.size());
	CYBOZU_TEST_EQUAL(s, s2);
}

void addTest()
{
	bls::SecretKey sec1, sec2;
	sec1.init();
	sec2.init();
	CYBOZU_TEST_ASSERT(sec1 != sec2);

	bls::PublicKey pub1, pub2;
	sec1.getPublicKey(pub1);
	sec2.getPublicKey(pub2);

	const std::string m = "doremi";
	bls::Sign s1, s2;
	sec1.sign(s1, m);
	sec2.sign(s2, m);
	CYBOZU_TEST_ASSERT((s1 + s2).verify(pub1 + pub2, m));
}

void dataTest()
{
	const size_t size = bls::getOpUnitSize() * sizeof(uint64_t);
	bls::SecretKey sec;
	sec.init();
	std::string str;
	sec.getData(str);
	{
		CYBOZU_TEST_EQUAL(str.size(), size);
		bls::SecretKey sec2;
		sec2.setData(str);
		CYBOZU_TEST_EQUAL(sec, sec2);
	}
	bls::PublicKey pub;
	sec.getPublicKey(pub);
	pub.getData(str);
	{
		CYBOZU_TEST_EQUAL(str.size(), size * 2);
		bls::PublicKey pub2;
		pub2.setData(str);
		CYBOZU_TEST_EQUAL(pub, pub2);
	}
	std::string m = "abc";
	bls::Sign sign;
	sec.sign(sign, m);
	sign.getData(str);
	{
		CYBOZU_TEST_EQUAL(str.size(), size);
		bls::Sign sign2;
		sign2.setData(str);
		CYBOZU_TEST_EQUAL(sign, sign2);
	}
	bls::Id id;
	const uint64_t v[] = { 1, 2, 3, 4, 5, 6, };
	id.set(v);
	id.getData(str);
	{
		CYBOZU_TEST_EQUAL(str.size(), size);
		bls::Id id2;
		id2.setData(str);
		CYBOZU_TEST_EQUAL(id, id2);
	}
}

void testAll()
{
	blsTest();
	k_of_nTest();
	popTest();
	addTest();
	dataTest();
}
CYBOZU_TEST_AUTO(all)
{
	const struct {
		int type;
		const char *name;
	} tbl[] = {
		{ bls::CurveFp254BNb, "Fp254" },
#if BLS_MAX_OP_UNIT_SIZE == 6
		{ bls::CurveFp382_1, "Fp382_1" },
		{ bls::CurveFp382_2, "Fp382_2" },
#endif
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		printf("curve=%s\n", tbl[i].name);
		bls::init(tbl[i].type);
		testAll();
	}
}
