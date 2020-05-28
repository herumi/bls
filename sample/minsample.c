#include <bls/bls384_256.h>
#include <stdio.h>

void simpleSample()
{
	blsSecretKey sec;
	blsSecretKeySetDecStr(&sec, "13", 2);
	blsPublicKey pub;
	blsGetPublicKey(&pub, &sec);
	blsSignature sig;
	const char *msg = "abc";
	size_t msgSize = 3;
	blsSign(&sig, &sec, msg, msgSize);
	printf("verify correct message %d\n", blsVerify(&sig, &pub, msg, msgSize));
	printf("verify wrong message %d\n", blsVerify(&sig, &pub, "xyz", msgSize));
}

void k_of_nSample()
{
#define N 5
#define K 3
	blsSecretKey secs[K]; // msk = secs[0]
	for (int i = 0; i < K; i++) {
		blsSecretKeySetByCSPRNG(&secs[i]);
	}
	// get master public key
	blsPublicKey mpk;
	blsGetPublicKey(&mpk, &secs[0]);
	blsId ids[N];
	blsSignature sigs[N];
	const char *msg = "abc";
	const size_t msgSize = strlen(msg);
	for (int i = 0; i < N; i++) {
		blsIdSetInt(&ids[i], i + 1);
		blsSecretKey sec;
		// sec is a secret key for ids[i] generated from secs[0..K-1]
		blsSecretKeyShare(&sec, secs, K, &ids[i]);
		blsSign(&sigs[i], &sec, msg, msgSize);
	}
	{
		blsSignature sig;
		// sig is recoverd from sigs[i] and ids [i] for i = 1, 2, 3(=K)
		blsSignatureRecover(&sig, &sigs[1], &ids[1], K);
		printf("verify=%d\n", blsVerify(&sig, &mpk, msg, msgSize));
	}
#undef K
#undef N
}

int main()
{
#ifdef BLS_ETH
	puts("BLS_ETH mode");
#else
	puts("no BLS_ETH mode");
#endif
	int r = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (r != 0) {
		printf("err blsInit %d\n", r);
		return 1;
	}
#ifdef BLS_ETH
	r = blsSetETHmode(BLS_ETH_MODE_DRAFT_07);
	if (r != 0) {
		printf("err blsSetETHmode %d\n", r);
		return 1;
	}
#endif
	simpleSample();
	k_of_nSample();
	return 0;
}
