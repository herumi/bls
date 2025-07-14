# java binding of bls


```
cd bls
make clean
make -C mcl clean
make -C mcl lib/libmcl.a
cd ffi/java
make test
```

## for Ethereum compatibility mode

```
cd bls
make clean
make -C mcl clean
make -C mcl lib/libmcl.a
cd ffi/java
make test BLS_ETH=1
```

## for Android

```
cd bls
ndk-build -C android/jni NDK_DEBUG=0 BLS_JAVA=1 BLS_ETH=1
```
then `libblsjava.so` is generated in `bls/android/libs/`.
