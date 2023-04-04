/*
make -C mcl lib/libmcl.a -j
make lib/libbls384_256.a -j
gcc sample/dfinity.c lib/libbls384_256.a -I include/ -I ./mcl/include/ ./mcl/lib/libmcl.a -lstdc++ -g && ./a.out
*/
#include <stdio.h>
#include <bls/bls384_256.h>
#include <stdint.h>
#include <string.h>

int initForDFINITY()
{
#ifdef BLS_ETH
	#error "don't define BLS_ETH"
#endif
	int ret = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (ret != 0) {
		printf("blsInit err %d\n", ret);
		return 1;
	}
	// set Ethereum serialization format.
	blsSetETHserialization(1);
	ret = blsSetMapToMode(MCL_MAP_TO_MODE_HASH_TO_CURVE);
	if (ret != 0) {
		printf("blsSetMapToMode err %d\n", ret);
		return 1;
	}
	// set the generator of G2. see https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-11.html#section-4.2.1
	blsPublicKey gen;
	const char *g2genStr = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
	ret = blsPublicKeySetHexStr(&gen, g2genStr, strlen(g2genStr));
	if (ret != 0) {
		printf("mclBnG2_setStr err %d\n", ret);
		return 1;
	}
	blsSetGeneratorOfPublicKey(&gen);
	// set domain_sep defined in https://docs.rs/ic-verify-bls-signature/0.1.0/src/ic_verify_bls_signature/lib.rs.html#32
	const char *dst = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
	mclBnG1_setDst(dst, strlen(dst));
	return 0;
}

int main()
{
	if (initForDFINITY() != 0) {
		return 1;
	}
	int ret;

	blsSecretKey sec;
	ret = blsSecretKeySetByCSPRNG(&sec);
	if (ret != 0) {
		printf("blsSecretKeySetByCSPRNG err %d\n", ret);
		return 1;
	}
	blsPublicKey pub;
	blsGetPublicKey(&pub, &sec);
	const size_t msgSize = 32;
	uint8_t msg[msgSize];
	memset(msg, 0, msgSize);
	msg[0] = 'a';
	blsSignature sig;
	ret = blsSignHash(&sig, &sec, msg, msgSize);
	if (ret != 0) {
		printf("blsSignHash err %d\n", ret);
		return 1;
	}
	ret = blsVerifyHash(&sig, &pub, msg, msgSize);
	printf("blsVerifyHash %d\n", ret);

	char buf[96];
	size_t n = blsPublicKeySerialize(buf, sizeof(buf), &pub);
	if (n != 96) {
		printf("blsPublicKeySerialize err %ld\n", n);
		return 1;
	}
	n = blsSignatureSerialize(buf, sizeof(buf), &sig);
	if (n != 48) {
		printf("blsSignatureSerialize err %ld\n", n);
		return 1;
	}
	// https://github.com/dfinity/agent-js/blob/5214dc1fc4b9b41f023a88b1228f04d2f2536987/packages/bls-verify/src/index.test.ts#L101
	const uint8_t pubByte[] = {
		0xa7, 0x62, 0x3a, 0x93, 0xcd, 0xb5, 0x6c, 0x4d, 0x23, 0xd9, 0x9c, 0x14, 0x21, 0x6a, 0xfa, 0xab, 0x3d, 0xfd, 0x6d, 0x4f, 0x9e, 0xb3, 0xdb, 0x23, 0xd0, 0x38, 0x28, 0x0b, 0x6d, 0x5c, 0xb2, 0xca, 0xae, 0xe2, 0xa1, 0x9d, 0xd9, 0x2c, 0x9d, 0xf7, 0x00, 0x1d, 0xed, 0xe2, 0x3b, 0xf0, 0x36, 0xbc, 0x0f, 0x33, 0x98, 0x2d, 0xfb, 0x41, 0xe8, 0xfa, 0x9b, 0x8e, 0x96, 0xb5, 0xdc, 0x3e, 0x83, 0xd5, 0x5c, 0xa4, 0xdd, 0x14, 0x6c, 0x7e, 0xb2, 0xe8, 0xb6, 0x85, 0x9c, 0xb5, 0xa5, 0xdb, 0x81, 0x5d, 0xb8, 0x68, 0x10, 0xb8, 0xd1, 0x2c, 0xee, 0x15, 0x88, 0xb5, 0xdb, 0xf3, 0x4a, 0x4d, 0xc9, 0xa5
	};
	n = blsPublicKeyDeserialize(&pub, pubByte, sizeof(pubByte));
	if (n != sizeof(pubByte)) {
		printf("blsPublicKeyDeserialize err %ld\n", n);
		return 1;
	}
	const uint8_t sigByte[] = {
		0xb8, 0x9e, 0x13, 0xa2, 0x12, 0xc8, 0x30, 0x58, 0x6e, 0xaa, 0x9a, 0xd5, 0x39, 0x46, 0xcd, 0x96, 0x87, 0x18, 0xeb, 0xec, 0xc2, 0x7e, 0xda, 0x84, 0x9d, 0x92, 0x32, 0x67, 0x3d, 0xcd, 0x4f, 0x44, 0x0e, 0x8b, 0x5d, 0xf3, 0x9b, 0xf1, 0x4a, 0x88, 0x04, 0x8c, 0x15, 0xe1, 0x6c, 0xbc, 0xaa, 0xbe

	};
	n = blsSignatureDeserialize(&sig, sigByte, sizeof(sigByte));
	if (n != sizeof(sigByte)) {
		printf("blsSignatureDeserialize err %ld\n", n);
		return 1;
	}
	const char *text = "hello";
	ret = blsVerify(&sig, &pub, text, strlen(text));
	printf("blsVerify ret=%d\n", ret);
	return 0;
}

