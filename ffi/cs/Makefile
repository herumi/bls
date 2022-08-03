all: bls_eth.cs

bls_eth.cs: bls.cs
	sed 's/public const bool isETH = false;/public const bool isETH = true;/' < bls.cs > bls_eth.cs