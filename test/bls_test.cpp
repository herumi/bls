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

	bls::MasterSecretKey msk;
	sec0.getMasterSecretKey(msk, k);

	std::vector<bls::SecretKey> allPrvVec(n);
	for (int i = 0; i < n; i++) {
		int id = i + 1;
		allPrvVec[i].set(msk, id);
	}
	CYBOZU_TEST_EQUAL(allPrvVec.size(), n);
	for (int i = 0; i < n; i++) {
		CYBOZU_TEST_EQUAL(allPrvVec[i].getId(), i + 1);
	}

	std::vector<bls::Sign> allSignVec(n);
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
	std::vector<bls::SecretKey> secVec(3);
	for (int a = 0; a < n; a++) {
		secVec[0] = allPrvVec[a];
		for (int b = a + 1; b < n; b++) {
			secVec[1] = allPrvVec[b];
			for (int c = b + 1; c < n; c++) {
				secVec[2] = allPrvVec[c];
				bls::SecretKey sec;
				sec.recover(secVec);
				CYBOZU_TEST_EQUAL(sec, sec0);
			}
		}
	}
	{
		secVec[0] = allPrvVec[0];
		secVec[1] = allPrvVec[1];
		secVec[2] = allPrvVec[0]; // same of secVec[0]
		bls::SecretKey sec;
		CYBOZU_TEST_EXCEPTION_MESSAGE(sec.recover(secVec), std::exception, "same id");
	}
	{
		/*
			n-out-of-n
			can recover
		*/
		bls::SecretKey sec;
		sec.recover(allPrvVec);
		CYBOZU_TEST_EQUAL(sec, sec0);
	}
	/*
		2-out-of-n
		can't recover
	*/
	secVec.resize(2);
	for (int a = 0; a < n; a++) {
		secVec[0] = allPrvVec[a];
		for (int b = a + 1; b < n; b++) {
			secVec[1] = allPrvVec[b];
			bls::SecretKey sec;
			sec.recover(secVec);
			CYBOZU_TEST_ASSERT(sec != sec0);
		}
	}
	/*
		3-out-of-n
		can recover
	*/
	std::vector<bls::Sign> signVec(3);
	for (int a = 0; a < n; a++) {
		signVec[0] = allSignVec[a];
		for (int b = a + 1; b < n; b++) {
			signVec[1] = allSignVec[b];
			for (int c = b + 1; c < n; c++) {
				signVec[2] = allSignVec[c];
				bls::Sign s;
				s.recover(signVec);
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
		s.recover(allSignVec);
		CYBOZU_TEST_EQUAL(s, s0);
	}
	/*
		2-out-of-n
		can't recover
	*/
	signVec.resize(2);
	for (int a = 0; a < n; a++) {
		signVec[0] = allSignVec[a];
		for (int b = a + 1; b < n; b++) {
			signVec[1] = allSignVec[b];
			bls::Sign s;
			s.recover(signVec);
			CYBOZU_TEST_ASSERT(s != s0);
		}
	}
	// share and recover publicKey
	{
		std::vector<bls::PublicKey> pubVec(k);
		// select [0, k) publicKey
		for (int i = 0; i < k; i++) {
			allPrvVec[i].getPublicKey(pubVec[i]);
		}
		bls::PublicKey pub;
		pub.recover(pubVec);
		CYBOZU_TEST_EQUAL(pub, pub0);
	}
}

CYBOZU_TEST_AUTO(MasterSecretKey)
{
	const int k = 3;
	const int n = 6;
	bls::SecretKey sec0;
	sec0.init();
	bls::PublicKey pub0;
	sec0.getPublicKey(pub0);
	bls::MasterSecretKey msk;
	sec0.getMasterSecretKey(msk, k);

	bls::MasterPublicKey mpk;
	bls::getMasterPublicKey(mpk, msk);

	const int idTbl[n] = {
		3, 5, 193, 22, 15
	};
	bls::SecretKeyVec secVec(n);
	bls::PublicKeyVec pubVec(n);
	for (int i = 0; i < n; i++) {
		int id = idTbl[i];
		secVec[i].set(msk, id);
		secVec[i].getPublicKey(pubVec[i]);
		bls::PublicKey pub;
		pub.set(mpk, id);
		CYBOZU_TEST_EQUAL(pubVec[i], pub);
	}
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
