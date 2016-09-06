package bls

/*
#cgo CFLAGS:-I../../include
#cgo LDFLAGS:-lbls -lbls_if -lmcl -lgmp -lgmpxx -L../lib -L../../lib -L../../../mcl/lib -L../../mcl/lib  -lstdc++ -lcrypto
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

func NewBlsId() *BlsId {
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

func (id *BlsId) SetStr(s string) {
	buf := []byte(s)
	err := C.blsIdSetStr(id.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err > 0 {
		fmt.Println("BlsId:SetStr", err)
	}
}

func (id *BlsId) Set(v []uint64) {
	if len(v) != 4 {
		fmt.Println("BlsId:set bad size", len(v))
		return
	}
	C.blsIdSet(id.self, (*C.uint64_t)(unsafe.Pointer(&v[0])))
}

type BlsSecretKey struct {
	self *C.blsSecretKey
}

func destroyBlsSecretKey(p *BlsSecretKey) {
	C.blsSecretKeyDestroy(p.self)
}

func NewBlsSecretKey() *BlsSecretKey {
	p := new(BlsSecretKey)
	p.self = C.blsSecretKeyCreate()
	runtime.SetFinalizer(p, destroyBlsSecretKey)
	return p
}

func (sec *BlsSecretKey) String() string {
	buf := make([]byte, 1024)
	n := C.blsSecretKeyGetStr(sec.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		return "err"
	}
	return string(buf[:n])
}

func (sec *BlsSecretKey) SetStr(s string) {
	buf := []byte(s)
	err := C.blsSecretKeySetStr(sec.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err > 0 {
		fmt.Println("BlsSecretKey:SetStr", err)
	}
}

func (sec *BlsSecretKey) Init() {
	C.blsSecretKeyInit(sec.self)
}

type BlsPublicKey struct {
	self *C.blsPublicKey
}

func destroyBlsPublicKey(p *BlsPublicKey) {
	C.blsPublicKeyDestroy(p.self)
}

func NewBlsPublicKey() *BlsPublicKey {
	p := new(BlsPublicKey)
	p.self = C.blsPublicKeyCreate()
	runtime.SetFinalizer(p, destroyBlsPublicKey)
	return p
}

func (pub *BlsPublicKey) String() string {
	buf := make([]byte, 1024)
	n := C.blsPublicKeyGetStr(pub.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		return "err"
	}
	return string(buf[:n])
}

func (pub *BlsPublicKey) SetStr(s string) {
	buf := []byte(s)
	err := C.blsPublicKeySetStr(pub.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err > 0 {
		fmt.Println("BlsPublicKey:SetStr", err)
	}
}

type BlsSign struct {
	self *C.blsSign
}

func destroyBlsSign(p *BlsSign) {
	C.blsSignDestroy(p.self)
}

func NewBlsSign() *BlsSign {
	p := new(BlsSign)
	p.self = C.blsSignCreate()
	runtime.SetFinalizer(p, destroyBlsSign)
	return p
}

func (sign *BlsSign) String() string {
	buf := make([]byte, 1024)
	n := C.blsSignGetStr(sign.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		return "err"
	}
	return string(buf[:n])
}

func (sign *BlsSign) SetStr(s string) {
	buf := []byte(s)
	err := C.blsSignSetStr(sign.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err > 0 {
		fmt.Println("BlsSign:SetStr", err)
	}
}

func (sec *BlsSecretKey) GetPublicKey() (pub *BlsPublicKey) {
	pub = NewBlsPublicKey()
	C.blsSecretKeyGetPublicKey(sec.self, pub.self)
	return pub
}

func (sec *BlsSecretKey) Sign(m string) (sign *BlsSign) {
	sign = NewBlsSign()
	buf := []byte(m)
	C.blsSecretKeySign(sec.self, sign.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	return sign
}

func (sign *BlsSign) Verify(pub *BlsPublicKey, m string) bool {
	buf := []byte(m)
	return C.blsSignVerify(sign.self, pub.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))) == 1
}

