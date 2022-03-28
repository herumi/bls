package bls

import (
	"unsafe"

	"github.com/herumi/mcl/ffi/go/mcl"
)

// SecretKey

func CastFromSecretKey(in *SecretKey) *mcl.Fr {
	return (*mcl.Fr)(unsafe.Pointer(in))
}

func CastToSecretKey(in *mcl.Fr) *SecretKey {
	return (*SecretKey)(unsafe.Pointer(in))
}

// PublicKey

func CastFromPublicKey(in *PublicKey) *mcl.G2 {
	return (*mcl.G2)(unsafe.Pointer(in))
}

func CastToPublicKey(in *mcl.G2) *PublicKey {
	return (*PublicKey)(unsafe.Pointer(in))
}

// Sign

func CastFromSign(in *Sign) *mcl.G1 {
	return (*mcl.G1)(unsafe.Pointer(in))
}

func CastToSign(in *mcl.G1) *Sign {
	return (*Sign)(unsafe.Pointer(in))
}
