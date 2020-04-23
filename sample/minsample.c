#ifdef BLS_ETH
#include <bls/bls384_256.h>
#else
#include <bls/bls384.h>
#endif
#include <stdio.h>

int main()
{
	int r = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (r != 0) {
		printf("err r=%d\n", r);
		return 1;
	}
	blsSecretKey sec;
	blsSecretKeySetDecStr(&sec, "13", 2);
	blsPublicKey pub;
	blsGetPublicKey(&pub, &sec);
	blsSignature sig;
	const char *msg = "abc";
	size_t msgSize = 3;
	blsSign(&sig, &sec, msg, msgSize);
	printf("%d\n", blsVerify(&sig, &pub, msg, msgSize));
	printf("%d\n", blsVerify(&sig, &pub, "xyz", msgSize));
	return 0;
}
