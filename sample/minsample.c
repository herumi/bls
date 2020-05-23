#include <bls/bls384_256.h>
#include <stdio.h>

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
	return 0;
}
