#include <bls/bls.hpp>
#include <cybozu/test.hpp>
#include <cybozu/inttype.hpp>
#include <iostream>
#include <sstream>
#include <array>
#include <cybozu/benchmark.hpp>
#include <cybozu/crypto.hpp>

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
	bls::init(MCL_BN254);
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
		bls::Signature sig;
		sec.sign(sig, m);
		CYBOZU_TEST_ASSERT(sig.verify(pub, m));
		CYBOZU_TEST_ASSERT(!sig.verify(pub, m + "a"));
		streamTest(sig);
		CYBOZU_BENCH_C("sign", 100, sec.sign, sig, m);
		CYBOZU_BENCH_C("verify", 100, sig.verify, pub, m);
	}
}

void k_of_nTest()
{
	const std::string m = "abc";
	const int n = 5;
	const int k = 3;
	bls::SecretKey sec0;
	sec0.init();
	bls::Signature sig0;
	sec0.sign(sig0, m);
	bls::PublicKey pub0;
	sec0.getPublicKey(pub0);
	CYBOZU_TEST_ASSERT(sig0.verify(pub0, m));

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

	bls::SignatureVec allSigVec(n);
	for (int i = 0; i < n; i++) {
		CYBOZU_TEST_ASSERT(allPrvVec[i] != sec0);
		allPrvVec[i].sign(allSigVec[i], m);
		bls::PublicKey pub;
		allPrvVec[i].getPublicKey(pub);
		CYBOZU_TEST_ASSERT(pub != pub0);
		CYBOZU_TEST_ASSERT(allSigVec[i].verify(pub, m));
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
	bls::SignatureVec sigVec(3);
	idVec.resize(3);
	for (int a = 0; a < n; a++) {
		sigVec[0] = allSigVec[a];
		idVec[0] = allIdVec[a];
		for (int b = a + 1; b < n; b++) {
			sigVec[1] = allSigVec[b];
			idVec[1] = allIdVec[b];
			for (int c = b + 1; c < n; c++) {
				sigVec[2] = allSigVec[c];
				idVec[2] = allIdVec[c];
				bls::Signature sig;
				sig.recover(sigVec, idVec);
				CYBOZU_TEST_EQUAL(sig, sig0);
			}
		}
	}
	{
		sigVec[0] = allSigVec[1]; idVec[0] = allIdVec[1];
		sigVec[1] = allSigVec[4]; idVec[1] = allIdVec[4];
		sigVec[2] = allSigVec[3]; idVec[2] = allIdVec[3];
		bls::Signature sig;
		CYBOZU_BENCH_C("sig.recover", 100, sig.recover, sigVec, idVec);
	}
	{
		/*
			n-out-of-n
			can recover
		*/
		bls::Signature sig;
		sig.recover(allSigVec, allIdVec);
		CYBOZU_TEST_EQUAL(sig, sig0);
	}
	/*
		2-out-of-n
		can't recover
	*/
	sigVec.resize(2);
	idVec.resize(2);
	for (int a = 0; a < n; a++) {
		sigVec[0] = allSigVec[a];
		idVec[0] = allIdVec[a];
		for (int b = a + 1; b < n; b++) {
			sigVec[1] = allSigVec[b];
			idVec[1] = allIdVec[b];
			bls::Signature sig;
			sig.recover(sigVec, idVec);
			CYBOZU_TEST_ASSERT(sig != sig0);
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
	bls::Signature sig0;
	sec0.sign(sig0, m);
	CYBOZU_TEST_ASSERT(sig0.verify(pub0, m));

	bls::SecretKeyVec msk;
	sec0.getMasterSecretKey(msk, k);

	bls::PublicKeyVec mpk;
	bls::getMasterPublicKey(mpk, msk);
	bls::SignatureVec  popVec;
	bls::getPopVec(popVec, msk);

	for (size_t i = 0; i < popVec.size(); i++) {
		CYBOZU_TEST_ASSERT(popVec[i].verify(mpk[i]));
	}

	const int idTbl[n] = {
		3, 5, 193, 22, 15
	};
	bls::SecretKeyVec secVec(n);
	bls::PublicKeyVec pubVec(n);
	bls::SignatureVec sVec(n);
	for (size_t i = 0; i < n; i++) {
		int id = idTbl[i];
		secVec[i].set(msk, id);
		secVec[i].getPublicKey(pubVec[i]);
		bls::PublicKey pub;
		pub.set(mpk, id);
		CYBOZU_TEST_EQUAL(pubVec[i], pub);

		bls::Signature pop;
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
	bls::Signature sig;
	sig.recover(sVec, idVec);
	CYBOZU_TEST_EQUAL(sig, sig0);
	bls::Signature sig2;
	sig2.recover(sVec.data(), idVec.data(), sVec.size());
	CYBOZU_TEST_EQUAL(sig, sig2);
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
	bls::Signature sig1, sig2;
	sec1.sign(sig1, m);
	sec2.sign(sig2, m);
	CYBOZU_TEST_ASSERT((sig1 + sig2).verify(pub1 + pub2, m));
}

void aggregateTest()
{
	const size_t n = 10;
	bls::SecretKey secs[n];
	bls::PublicKey pubs[n], pub;
	bls::Signature sigs[n], sig;
	const std::string m = "abc";
	for (size_t i = 0; i < n; i++) {
		secs[i].init();
		secs[i].getPublicKey(pubs[i]);
		secs[i].sign(sigs[i], m);
	}
	pub = pubs[0];
	sig = sigs[0];
	for (size_t i = 1; i < n; i++) {
		pub.add(pubs[i]);
		sig.add(sigs[i]);
	}
	CYBOZU_TEST_ASSERT(sig.verify(pub, m));
}

void verifyAggregateTest()
{
	const size_t n = 10;
	bls::SecretKey secs[n];
	bls::PublicKey pubs[n];
	bls::Signature sigs[n], sig;
	std::vector<char[32]> h(n);
	for (size_t i = 0; i < n; i++) {
	    char msg[128];
	    sprintf(msg, "abc-%d", (int)i);

        cybozu::crypto::Hash  hash(cybozu::crypto::Hash::N_SHA256);
        hash.digest(h[i], msg, strlen(msg));

		secs[i].init();
		secs[i].getPublicKey(pubs[i]);
		secs[i].signHash(sigs[i], h[i], 32);
	}
	sig = sigs[0];
	for (size_t i = 1; i < n; i++) {
		sig.add(sigs[i]);
	}
    CYBOZU_TEST_ASSERT(sig.verifyAggregatedHashes(pubs, h.data(), 32, n));

	bls::Signature invalidSig = sigs[0] + sigs[1];
    CYBOZU_TEST_ASSERT(!invalidSig.verifyAggregatedHashes(pubs, h.data(), 32, n));

    h[0][0]++;
    CYBOZU_TEST_ASSERT(!sig.verifyAggregatedHashes(pubs, h.data(), 32, n));
}


void dataTest()
{
	const size_t FrSize = bls::getFrByteSize();
	const size_t FpSize = bls::getG1ByteSize();
	bls::SecretKey sec;
	sec.init();
	std::string str;
	sec.getStr(str, bls::IoFixedByteSeq);
	{
		CYBOZU_TEST_EQUAL(str.size(), FrSize);
		bls::SecretKey sec2;
		sec2.setStr(str, bls::IoFixedByteSeq);
		CYBOZU_TEST_EQUAL(sec, sec2);
	}
	bls::PublicKey pub;
	sec.getPublicKey(pub);
	pub.getStr(str, bls::IoFixedByteSeq);
	{
		CYBOZU_TEST_EQUAL(str.size(), FpSize * 2);
		bls::PublicKey pub2;
		pub2.setStr(str, bls::IoFixedByteSeq);
		CYBOZU_TEST_EQUAL(pub, pub2);
	}
	std::string m = "abc";
	bls::Signature sign;
	sec.sign(sign, m);
	sign.getStr(str, bls::IoFixedByteSeq);
	{
		CYBOZU_TEST_EQUAL(str.size(), FpSize);
		bls::Signature sign2;
		sign2.setStr(str, bls::IoFixedByteSeq);
		CYBOZU_TEST_EQUAL(sign, sign2);
	}
	bls::Id id;
	const uint64_t v[] = { 1, 2, 3, 4, 5, 6, };
	id.set(v);
	id.getStr(str, bls::IoFixedByteSeq);
	{
		CYBOZU_TEST_EQUAL(str.size(), FrSize);
		bls::Id id2;
		id2.setStr(str, bls::IoFixedByteSeq);
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
	aggregateTest();
	verifyAggregateTest();
}
CYBOZU_TEST_AUTO(all)
{
	const struct {
		int type;
		const char *name;
	} tbl[] = {
		{ MCL_BN254, "BN254" },
#if MCLBN_FP_UNIT_SIZE == 6
		{ MCL_BN381_1, "BN381_1" },
		{ MCL_BLS12_381, "BLS12_381" },
#endif
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		printf("curve=%s\n", tbl[i].name);
		bls::init(tbl[i].type);
		testAll();
	}
}
