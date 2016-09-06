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

	id := C.blsIdCreate()
	defer C.blsIdDestroy(id)

	C.blsIdSet(id, (*C.uint64_t)(unsafe.Pointer(&[]uint64{1, 2, 3, 4}[0])))
	C.blsIdPut(id)

	fmt.Println("create secret key")
	sec := C.blsSecretKeyCreate()
	defer C.blsSecretKeyDestroy(sec)
	C.blsSecretKeyInit(sec)
	C.blsSecretKeyPut(sec)

	fmt.Println("create public key")
	pub := C.blsPublicKeyCreate()
	defer C.blsPublicKeyDestroy(pub)
	C.blsSecretKeyGetPublicKey(sec, pub)

	C.blsPublicKeyPut(pub)

	sign := C.blsSignCreate()
	defer C.blsSignDestroy(sign)

	msg := []byte("Hello bls")
	fmt.Println("sign message")
	C.blsSecretKeySign(sec, sign, (*C.char)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)))

	C.blsSignPut(sign)

	fmt.Println("verify:", C.blsSignVerify(sign, pub, (*C.char)(unsafe.Pointer(&msg[0])), C.size_t(len(msg))))

}
