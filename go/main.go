package main

import "fmt"
import "./bls"

func testRecoverSecretKey() {
	fmt.Println("testRecoverSecretKey")
	k := 5
	sec := bls.NewSecretKey()
	sec.Init()
	fmt.Println("sec =", sec)

	// make master secret key
	msk := sec.GetMasterSecretKey(k)

	n := k
	secVec := make([]bls.SecretKey, n)
	idVec := make([]bls.Id, n)
	for i := 0; i < n; i++ {
		idVec[i] = *bls.NewId()
		idVec[i].Set([]uint64{1, 2, 3, uint64(i)})
		secVec[i] = *bls.NewSecretKey()
		secVec[i].Set(msk, idVec[i])
	}
	// recover sec2 from secVec and idVec
	sec2 := bls.NewSecretKey()
	sec2.Recover(secVec, idVec)
	fmt.Println("sec2=", sec2)
}

func main() {
	fmt.Println("init")
	bls.Init()
	{
		id := bls.NewId()
		id.Set([]uint64{4, 3, 2, 1})
		fmt.Println("id :", id)
		id2 := bls.NewId()
		id2.SetStr(id.String())
		fmt.Println("id2:", id2)
	}

	fmt.Println("create secret key")
	m := "this is a bls sample for go"
	sec := bls.NewSecretKey()
	sec.Init()
	fmt.Println("sec:", sec)
	fmt.Println("create public key")
	pub := sec.GetPublicKey()
	fmt.Println("pub:", pub)
	sign := sec.Sign(m)
	fmt.Println("sign:", sign)
	fmt.Println("verify:", sign.Verify(pub, m))

	// How to make array of SecretKey
	{
		sec := make([]bls.SecretKey, 3)
		for i := 0; i < len(sec); i++ {
			sec[i] = *bls.NewSecretKey()
			sec[i].Init()
			fmt.Println("sec=", sec[i].String())
		}
	}
	testRecoverSecretKey()
}
