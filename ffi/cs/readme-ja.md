# BLS署名のC#バインディング

# 必要環境

* Visual Studio 2017(x64) or later
* C# 7.2 or later
* .NET Framework 4.5.2 or later

# DLLのビルド方法

Visual Studio 2017の64bit用コマンドプロンプトを開いて
```
md work
cd work
git clone https://github.com/herumi/cybozulib_ext
git clone https://github.com/herumi/mcl
git clone https://github.com/herumi/bls
cd bls
mklib dll
```
としてbls/binにDLLを作成する。

# サンプルのビルド方法

bls/ffi/cs/bls.slnを開いて実行する。

* 注意 bls256.slnは古いため使わないでください。

# ライセンス

modified new BSD License
http://opensource.org/licenses/BSD-3-Clause

# 著者

光成滋生 MITSUNARI Shigeo(herumi@nifty.com)
