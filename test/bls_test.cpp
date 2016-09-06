#include <bls.hpp>
#include <cybozu/test.hpp>
#include <iostream>
#include <sstream>

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

CYBOZU_TEST_AUTO(bls)
{
	bls::init();
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
	}
}

CYBOZU_TEST_AUTO(id)
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
	{
		/*
			exception if the value >= r
		*/
		const uint64_t id1[] = { 0, 0, 0, uint64_t(-1) };
		CYBOZU_TEST_EXCEPTION(id.set(id1), std::exception);
	}
}

CYBOZU_TEST_AUTO(k_of_n)
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

	std::vector<const bls::SecretKey*> pmsk(k);
	for (size_t i = 0; i < k; i++) {
		pmsk[i] = &msk[i];
	}

	bls::SecretKeyVec allPrvVec(n);
	bls::IdVec allIdVec(n);
	for (int i = 0; i < n; i++) {
		int id = i + 1;
		allPrvVec[i].set(msk, id);
		allIdVec[i] = id;

		bls::SecretKey p;
		p.set(&pmsk[0], k, id);
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
	}
}

CYBOZU_TEST_AUTO(pop)
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
}

CYBOZU_TEST_AUTO(add)
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
