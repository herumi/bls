package bls

import "unsafe"

// allow zero length byte
func getPointer(msg []byte) unsafe.Pointer {
	if len(msg) == 0 {
		return nil
	}
	return unsafe.Pointer(&msg[0])
}
