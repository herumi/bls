# java binding of bls


```
cd bls
make clean
make lib/libmcl.a
cd ffi/java
make test
```

## for Ethereum compatibility mode

```
cd bls
make clean
make lib/libmcl.a
cd ffi/java
make test BLS_ETH=1
```
