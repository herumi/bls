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
	bls::PrivateKey prv;
	prv.init();
	streamTest(prv);
	bls::PublicKey pub;
	prv.getPublicKey(pub);
	streamTest(pub);
	for (int i = 0; i < 5; i++) {
		std::string m = "hello";
		m += char('0' + i);
		bls::Sign s;
		prv.sign(s, m);
		CYBOZU_TEST_ASSERT(pub.verify(s, m));
		CYBOZU_TEST_ASSERT(!pub.verify(s, m + "a"));
		streamTest(s);
	}
}

CYBOZU_TEST_AUTO(k_of_n)
{
	const std::string m = "abc";
	const int n = 5;
	const int k = 3;
	bls::PrivateKey prv0;
	prv0.init();
	bls::Sign s0;
	prv0.sign(s0, m);
	bls::PublicKey pub0;
	prv0.getPublicKey(pub0);
	CYBOZU_TEST_ASSERT(pub0.verify(s0, m));

	std::vector<bls::PrivateKey> allPrvVec;
	prv0.share(allPrvVec, n, k);
	CYBOZU_TEST_EQUAL(allPrvVec.size(), n);
	for (int i = 0; i < n; i++) {
		CYBOZU_TEST_EQUAL(allPrvVec[i].getId(), i + 1);
	}

	std::vector<bls::Sign> allSignVec(n);
	for (int i = 0; i < n; i++) {
		CYBOZU_TEST_ASSERT(allPrvVec[i] != prv0);
		allPrvVec[i].sign(allSignVec[i], m);
		bls::PublicKey pub;
		allPrvVec[i].getPublicKey(pub);
		CYBOZU_TEST_ASSERT(pub != pub0);
		CYBOZU_TEST_ASSERT(pub.verify(allSignVec[i], m));
	}

	/*
		3-out-of-n
		can recover
	*/
	std::vector<bls::PrivateKey> prvVec(3);
	for (int a = 0; a < n; a++) {
		prvVec[0] = allPrvVec[a];
		for (int b = a + 1; b < n; b++) {
			prvVec[1] = allPrvVec[b];
			for (int c = b + 1; c < n; c++) {
				prvVec[2] = allPrvVec[c];
				bls::PrivateKey prv;
				prv.recover(prvVec);
				CYBOZU_TEST_EQUAL(prv, prv0);
			}
		}
	}
	{
		prvVec[0] = allPrvVec[0];
		prvVec[1] = allPrvVec[1];
		prvVec[2] = allPrvVec[0]; // same of prvVec[0]
		bls::PrivateKey prv;
		CYBOZU_TEST_EXCEPTION_MESSAGE(prv.recover(prvVec), std::exception, "same id");
	}
	{
		/*
			n-out-of-n
			can recover
		*/
		bls::PrivateKey prv;
		prv.recover(allPrvVec);
		CYBOZU_TEST_EQUAL(prv, prv0);
	}
	/*
		2-out-of-n
		can't recover
	*/
	prvVec.resize(2);
	for (int a = 0; a < n; a++) {
		prvVec[0] = allPrvVec[a];
		for (int b = a + 1; b < n; b++) {
			prvVec[1] = allPrvVec[b];
			bls::PrivateKey prv;
			prv.recover(prvVec);
			CYBOZU_TEST_ASSERT(prv != prv0);
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

CYBOZU_TEST_AUTO(verifier)
{
	const int n = 6;
	const int k = 3;
	bls::PrivateKey prv0;
	prv0.init();
	bls::PublicKey pub0;
	prv0.getPublicKey(pub0);
	std::vector<bls::PrivateKey> prvVec;
	bls::MasterPublicKey mpk;
	prv0.share(prvVec, n, k, &mpk);
	CYBOZU_TEST_ASSERT(pub0.isValid(mpk));
	for (size_t i = 0; i < prvVec.size(); i++) {
		bls::PublicKey pub;
		prvVec[i].getPublicKey(pub);
		CYBOZU_TEST_ASSERT(pub.isValid(mpk));
	}
	streamTest(mpk);
}
