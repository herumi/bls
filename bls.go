package main

// #cgo LDFLAGS: -Llib -L../mcl/lib -lbls -lmcl -lstdc++ -lgmp -lgmpxx -lcrypto 
// #include "include/bls.h"
import "C"

func main() {
        C.mybls()
}
