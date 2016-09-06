package main

/*
#cgo CFLAGS:-I../include
#cgo LDFLAGS:-lbls -lbls_if -lmcl -lgmp -lgmpxx -L../lib -L../../mcl/lib -lstdc++ -lcrypto
#include "bls_if.h"
*/
import "C"
import "fmt"
import "unsafe"

func main() {
	fmt.Println("init")
	C.blsInit()

	fmt.Println("create secret key")
	sec := C.blsSecretKeyCreate()
	C.blsSecretKeyInit(sec)
	C.blsSecretKeyPut(sec)

	fmt.Println("create public key")
	pub := C.blsPublicKeyCreate()
	C.blsSecretKeyGetPublicKey(sec, pub)

	C.blsPublicKeyPut(pub)

	sign := C.blsSignCreate()

	msg := []byte("Hello bls")
	fmt.Println("sign message")
	C.blsSecretKeySign(sec, sign, (*C.char)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)))

	C.blsSignPut(sign)

	fmt.Println("verify:", C.blsSignVerify(sign, pub, (*C.char)(unsafe.Pointer(&msg[0])), C.size_t(len(msg))))

	C.blsPublicKeyDestroy(pub)
	C.blsSecretKeyDestroy(sec)
}
