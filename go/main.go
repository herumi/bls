package main

import "fmt"
import "./bls"

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
}
