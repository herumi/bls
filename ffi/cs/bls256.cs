þ½Ž¿using System;
using System.Text;
using System.Runtime.InteropServices;

namespace mcl {
	class BLS256 {
		const int IoEcComp = 512; // fixed byte representation
		public const int maxUnitSize = 4;
		[DllImport("bls256.dll")]
		public static extern int blsInit(int curve, int maxUnitSize);

		[DllImport("bls256.dll")] public static extern void blsIdSetInt(ref Id id, int x);
		[DllImport("bls256.dll")] public static extern int blsIdSetDecStr(ref Id id, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport("bls256.dll")] public static extern int blsIdSetHexStr(ref Id id, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport("bls256.dll")] public static extern ulong blsIdGetDecStr([Out]StringBuilder buf, ulong maxBufSize, ref Id id);
		[DllImport("bls256.dll")] public static extern ulong blsIdGetHexStr([Out]StringBuilder buf, ulong maxBufSize, ref Id id);


		[DllImport("bls256.dll")] public static extern ulong blsIdSerialize([Out]StringBuilder buf, ulong maxBufSize, ref Id id);
		[DllImport("bls256.dll")] public static extern ulong blsSecretKeySerialize([Out]StringBuilder buf, ulong maxBufSize, ref SecretKey sec);
		[DllImport("bls256.dll")] public static extern ulong blsPublicKeySerialize([Out]StringBuilder buf, ulong maxBufSize, ref PublicKey pub);
		[DllImport("bls256.dll")] public static extern ulong blsSignatureSerialize([Out]StringBuilder buf, ulong maxBufSize, ref Signature sig);

		[DllImport("bls256.dll")] public static extern int blsIdDeserialize(ref Id id, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport("bls256.dll")] public static extern int blsSecretKeyDeserialize(ref SecretKey sec, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport("bls256.dll")] public static extern int blsPublicKeyDeserialize(ref PublicKey pub, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport("bls256.dll")] public static extern int blsSignatureDeserialize(ref Signature sig, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);

		[DllImport("bls256.dll")] public static extern int blsIdIsEqual(ref Id lhs, ref Id rhs);
		[DllImport("bls256.dll")] public static extern int blsSecretKeyIsEqual(ref SecretKey lhs, ref SecretKey rhs);
		[DllImport("bls256.dll")] public static extern int blsPublicKeyIsEqual(ref PublicKey lhs, ref PublicKey rhs);
		[DllImport("bls256.dll")] public static extern int blsSignatureIsEqual(ref Signature lhs, ref Signature rhs);

		// add
		[DllImport("bls256.dll")] public static extern void blsSecretKeyAdd(ref SecretKey sec, ref SecretKey rhs);
		[DllImport("bls256.dll")] public static extern void blsPublicKeyAdd(ref PublicKey pub, ref PublicKey rhs);
		[DllImport("bls256.dll")] public static extern void blsSignatureAdd(ref Signature sig, ref Signature rhs);

		//	hash buf and set
		[DllImport("bls256.dll")] public static extern int blsHashToSecretKey(ref SecretKey sec, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		/*
			set secretKey if system has /dev/urandom or CryptGenRandom
			return 0 if success else -1
		*/
		[DllImport("bls256.dll")] public static extern int blsSecretKeySetByCSPRNG(ref SecretKey sec);

		[DllImport("bls256.dll")] public static extern void blsGetPublicKey(ref PublicKey pub, ref SecretKey sec);
		[DllImport("bls256.dll")] public static extern void blsGetPop(ref Signature sig, ref SecretKey sec);

		// return 0 if success
		[DllImport("bls256.dll")] public static extern int blsSecretKeyShare(ref SecretKey sec, ref SecretKey msk, ulong k, ref Id id);
		[DllImport("bls256.dll")] public static extern int blsPublicKeyShare(ref PublicKey pub, ref PublicKey mpk, ulong k, ref Id id);


		[DllImport("bls256.dll")] public static extern int blsSecretKeyRecover(ref SecretKey sec, ref SecretKey secVec, ref Id idVec, ulong n);
		[DllImport("bls256.dll")] public static extern int blsPublicKeyRecover(ref PublicKey pub, ref PublicKey pubVec, ref Id idVec, ulong n);
		[DllImport("bls256.dll")] public static extern int blsSignatureRecover(ref Signature sig, ref Signature sigVec, ref Id idVec, ulong n);

		[DllImport("bls256.dll")] public static extern void blsSign(ref Signature sig, ref SecretKey sec, [In][MarshalAs(UnmanagedType.LPStr)] string m, ulong size);

		// return 1 if valid
		[DllImport("bls256.dll")] public static extern int blsVerify(ref Signature sig, ref PublicKey pub, [In][MarshalAs(UnmanagedType.LPStr)] string m, ulong size);
		[DllImport("bls256.dll")] public static extern int blsVerifyPop(ref Signature sig, ref PublicKey pub);

		//////////////////////////////////////////////////////////////////////////
		// the following apis will be removed

		// mask buf with (1 << (bitLen(r) - 1)) - 1 if buf >= r
		[DllImport("bls256.dll")] public static extern int blsIdSetLittleEndian(ref Id id, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		/*
			return written byte size if success else 0
		*/
		[DllImport("bls256.dll")] public static extern ulong blsIdGetLittleEndian([Out]StringBuilder buf, ulong maxBufSize, ref Id id);

		// return 0 if success
		// mask buf with (1 << (bitLen(r) - 1)) - 1 if buf >= r
		[DllImport("bls256.dll")] public static extern int blsSecretKeySetLittleEndian(ref SecretKey sec, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport("bls256.dll")] public static extern int blsSecretKeySetDecStr(ref SecretKey sec, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport("bls256.dll")] public static extern int blsSecretKeySetHexStr(ref SecretKey sec, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		/*
			return written byte size if success else 0
		*/
		[DllImport("bls256.dll")] public static extern ulong blsSecretKeyGetLittleEndian([Out]StringBuilder buf, ulong maxBufSize, ref SecretKey sec);
		/*
			return strlen(buf) if success else 0
			buf is '\0' terminated
		*/
		[DllImport("bls256.dll")] public static extern ulong blsSecretKeyGetDecStr([Out]StringBuilder buf, ulong maxBufSize, ref SecretKey sec);
		[DllImport("bls256.dll")] public static extern ulong blsSecretKeyGetHexStr([Out]StringBuilder buf, ulong maxBufSize, ref SecretKey sec);
		[DllImport("bls256.dll")] public static extern int blsPublicKeySetHexStr(ref PublicKey pub, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport("bls256.dll")] public static extern ulong blsPublicKeyGetHexStr([Out]StringBuilder buf, ulong maxBufSize, ref PublicKey pub);
		[DllImport("bls256.dll")] public static extern int blsSignatureSetHexStr(ref Signature sig, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport("bls256.dll")] public static extern ulong blsSignatureGetHexStr([Out]StringBuilder buf, ulong maxBufSize, ref Signature sig);

		public static void Init()
		{
			const int CurveFp254BNb = 0;
			if (!System.Environment.Is64BitProcess) {
				throw new PlatformNotSupportedException("not 64-bit system");
			}
			int err = blsInit(CurveFp254BNb, maxUnitSize);
			if (err != 0) {
				throw new ArgumentException("blsInit");
			}
		}

		public struct Id {
			private ulong v0, v1, v2, v3;
			public bool IsEqual(Id rhs)
			{
				return blsIdIsEqual(ref this, ref rhs) != 0;
			}
			public void SetDecStr(String s)
			{
				if (blsIdSetDecStr(ref this, s, (ulong)s.Length) != 0) {
					throw new ArgumentException("blsIdSetDecSt:" + s);
				}
			}
			public void SetHexStr(String s)
			{
				if (blsIdSetHexStr(ref this, s, (ulong)s.Length) != 0) {
					throw new ArgumentException("blsIdSetHexStr:" + s);
				}
			}
			public void SetInt(int x)
			{
				blsIdSetInt(ref this, x);
			}
			public string GetDecStr()
			{
				StringBuilder sb = new StringBuilder(1024);
				ulong size = blsIdGetDecStr(sb, (ulong)sb.Capacity, ref this);
				if (size == 0) {
					throw new ArgumentException("blsIdGetDecStr");
				}
				return sb.ToString(0, (int)size);
			}
			public string GetHexStr()
			{
				StringBuilder sb = new StringBuilder(1024);
				ulong size = blsIdGetHexStr(sb, (ulong)sb.Capacity, ref this);
				if (size == 0) {
					throw new ArgumentException("blsIdGetHexStr");
				}
				return sb.ToString(0, (int)size);
			}
		}
		public struct SecretKey {
			private ulong v0, v1, v2, v3;
			public bool IsEqual(SecretKey rhs)
			{
				return blsSecretKeyIsEqual(ref this, ref rhs) != 0;
			}
			public void SetHexStr(String s)
			{
				if (blsSecretKeySetHexStr(ref this, s, (ulong)s.Length) != 0) {
					throw new ArgumentException("blsSecretKeySetHexStr:" + s);
				}
			}
			public string GetHexStr()
			{
				StringBuilder sb = new StringBuilder(1024);
				ulong size = blsSecretKeyGetHexStr(sb, (ulong)sb.Capacity, ref this);
				if (size == 0) {
					throw new ArgumentException("mclBnFr_getStr");
				}
				return sb.ToString(0, (int)size);
			}
			public void Add(SecretKey rhs)
			{
				blsSecretKeyAdd(ref this, ref rhs);
			}
			public void SetByCSPRNG()
			{
				blsSecretKeySetByCSPRNG(ref this);
			}
			public void SetHashOf(string s)
			{
				if (blsHashToSecretKey(ref this, s, (ulong)s.Length) != 0) {
					throw new ArgumentException("blsHashToSecretKey");
				}
			}
			public PublicKey GetPublicKey()
			{
				PublicKey pub = new PublicKey();
				blsGetPublicKey(ref pub, ref this);
				return pub;
			}
			public Signature Signature(String m)
			{
				Signature Signature = new Signature();
				blsSign(ref Signature, ref this, m, (ulong)m.Length);
				return Signature;
			}
		}
		// secretKey = sum_{i=0}^{msk.Length - 1} msk[i] * id^i
		public static SecretKey ShareSecretKey(SecretKey[] msk, Id id)
		{
			SecretKey sec = new SecretKey();
			if (blsSecretKeyShare(ref sec, ref msk[0], (ulong)msk.Length, ref id) != 0) {
				throw new ArgumentException("GetSecretKeyForId:" + id.ToString());
			}
			return sec;
		}
		public static SecretKey RecoverSecretKey(SecretKey[] secs, Id[] ids)
		{
			SecretKey sec = new SecretKey();
			if (blsSecretKeyRecover(ref sec, ref secs[0], ref ids[0], (ulong)secs.Length) != 0) {
				throw new ArgumentException("Recover");
			}
			return sec;
		}
		public struct PublicKey {
			private ulong v00, v01, v02, v03, v04, v05, v06, v07, v08, v09, v10, v11;
			private ulong v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23;
			public bool IsEqual(PublicKey rhs)
			{
				return blsPublicKeyIsEqual(ref this, ref rhs) != 0;
			}
			public void SetStr(String s)
			{
				if (blsPublicKeySetHexStr(ref this, s, (ulong)s.Length) != 0) {
					throw new ArgumentException("blsPublicKeySetStr:" + s);
				}
			}
			public string GetHexStr()
			{
				StringBuilder sb = new StringBuilder(1024);
				ulong size = blsPublicKeyGetHexStr(sb, (ulong)sb.Capacity, ref this);
				if (size == 0) {
					throw new ArgumentException("blsPublicKeyGetStr");
				}
				return sb.ToString(0, (int)size);
			}
			public void Add(PublicKey rhs)
			{
				blsPublicKeyAdd(ref this, ref rhs);
			}
			public bool Verify(Signature Signature, string m)
			{
				return blsVerify(ref Signature, ref this, m, (ulong)m.Length) == 1;
			}
		}
		// publicKey = sum_{i=0}^{mpk.Length - 1} mpk[i] * id^i
		public static PublicKey SharePublicKey(PublicKey[] mpk, Id id)
		{
			PublicKey pub = new PublicKey();
			if (blsPublicKeyShare(ref pub, ref mpk[0], (ulong)mpk.Length, ref id) != 0) {
				throw new ArgumentException("GetPublicKeyForId:" + id.ToString());
			}
			return pub;
		}
		public static PublicKey RecoverPublicKey(PublicKey[] pubs, Id[] ids)
		{
			PublicKey pub = new PublicKey();
			if (blsPublicKeyRecover(ref pub, ref pubs[0], ref ids[0], (ulong)pubs.Length) != 0) {
				throw new ArgumentException("Recover");
			}
			return pub;
		}
		public struct Signature {
			private ulong v00, v01, v02, v03, v04, v05, v06, v07, v08, v09, v10, v11;
			public bool IsEqual(Signature rhs)
			{
				return blsSignatureIsEqual(ref this, ref rhs) != 0;
			}
			public void SetStr(String s)
			{
				if (blsSignatureSetHexStr(ref this, s, (ulong)s.Length) != 0) {
					throw new ArgumentException("blsSignatureSetStr:" + s);
				}
			}
			public string GetHexStr()
			{
				StringBuilder sb = new StringBuilder(1024);
				ulong size = blsSignatureGetHexStr(sb, (ulong)sb.Capacity, ref this);
				if (size == 0) {
					throw new ArgumentException("blsSignatureGetStr");
				}
				return sb.ToString(0, (int)size);
			}
			public void Add(Signature rhs)
			{
				blsSignatureAdd(ref this, ref rhs);
			}
		}
		public static Signature RecoverSign(Signature[] signs, Id[] ids)
		{
			Signature Signature = new Signature();
			if (blsSignatureRecover(ref Signature, ref signs[0], ref ids[0], (ulong)signs.Length) != 0) {
				throw new ArgumentException("Recover");
			}
			return Signature;
		}
	}
}
