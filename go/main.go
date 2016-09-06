package main

/*
#cgo CFLAGS:-I../include
#cgo LDFLAGS:-lbls -lbls_if -lmcl -lgmp -lgmpxx -L../lib -L../../mcl/lib -lstdc++ -lcrypto
#include "bls_if.h"
*/
import "C"
import "fmt"
import "runtime"
import "unsafe"

func BlsInit() {
	C.blsInit()
}

type BlsId struct {
	self *C.blsId
}

func destroyBlsId(p *BlsId) {
	C.blsIdDestroy(p.self)
}

func newBlsId() *BlsId {
	p := new(BlsId)
	p.self = C.blsIdCreate()
	runtime.SetFinalizer(p, destroyBlsId)
	return p
}

func (id *BlsId) String() string {
	buf := make([]byte, 1024)
	n := C.blsIdGetStr(id.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		return "err"
	}
	return string(buf[:n])
}

func (id *BlsId) setStr(s string) {
	buf := []byte(s)
	err := C.blsIdSetStr(id.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err > 0 {
		fmt.Println("BlsId:SetStr", err)
	}
}

func (id *BlsId) set(v []uint64) {
	C.blsIdSet(id.self, (*C.uint64_t)(unsafe.Pointer(&v[0])))
}

func main() {
	fmt.Println("init")
	BlsInit()
	{
		id := newBlsId()
		id.set([]uint64{4, 3, 2, 1})
		fmt.Println("id :", id)
		id2 := newBlsId()
		id2.setStr(id.String())
		fmt.Println("id2:", id2)
	}

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
