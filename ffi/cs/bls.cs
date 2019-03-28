þ½Ž¿using System;
using System.Text;
using System.Runtime.InteropServices;

namespace mcl {
	class BLS {
        public const int BN254 = 0;
        public const int BLS12_381 = 5;

        const int IoEcComp = 512; // fixed byte representation
        public const int FR_UNIT_SIZE = 4;
        public const int FP_UNIT_SIZE = 6; // 4 if bls256.dll is used
        public const int COMPILED_TIME_VAR = FR_UNIT_SIZE * 10 + FP_UNIT_SIZE;

        public const int ID_UNIT_SIZE = FR_UNIT_SIZE;
        public const int SECRETKEY_UNIT_SIZE = FR_UNIT_SIZE;
        public const int PUBLICKEY_UNIT_SIZE = FP_UNIT_SIZE * 3 * 2;
        public const int SIGNATURE_UNIT_SIZE = FP_UNIT_SIZE * 3;

        public const string dllName = FP_UNIT_SIZE == 4 ? "bls256.dll" : "bls384_256.dll";
		[DllImport(dllName)]
		public static extern int blsInit(int curveType, int compiledTimeVar);

		[DllImport(dllName)] public static extern void blsIdSetInt(ref Id id, int x);
		[DllImport(dllName)] public static extern int blsIdSetDecStr(ref Id id, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport(dllName)] public static extern int blsIdSetHexStr(ref Id id, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport(dllName)] public static extern ulong blsIdGetDecStr([Out]StringBuilder buf, ulong maxBufSize, in Id id);
		[DllImport(dllName)] public static extern ulong blsIdGetHexStr([Out]StringBuilder buf, ulong maxBufSize, in Id id);

		[DllImport(dllName)] public static extern ulong blsIdSerialize([Out]StringBuilder buf, ulong maxBufSize, in Id id);
        [DllImport(dllName)] public static extern ulong blsSecretKeySerialize([Out]StringBuilder buf, ulong maxBufSize, in SecretKey sec);
		[DllImport(dllName)] public static extern ulong blsPublicKeySerialize([Out]StringBuilder buf, ulong maxBufSize, in PublicKey pub);
		[DllImport(dllName)] public static extern ulong blsSignatureSerialize([Out]StringBuilder buf, ulong maxBufSize, in Signature sig);
        [DllImport(dllName)] public static extern int blsIdDeserialize(ref Id id, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
        [DllImport(dllName)] public static extern int blsSecretKeyDeserialize(ref SecretKey sec, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport(dllName)] public static extern int blsPublicKeyDeserialize(ref PublicKey pub, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport(dllName)] public static extern int blsSignatureDeserialize(ref Signature sig, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);

        [DllImport(dllName)] public static extern int blsIdIsEqual(in Id lhs, in Id rhs);
        [DllImport(dllName)] public static extern int blsSecretKeyIsEqual(in SecretKey lhs, in SecretKey rhs);
        [DllImport(dllName)] public static extern int blsPublicKeyIsEqual(in PublicKey lhs, in PublicKey rhs);
		[DllImport(dllName)] public static extern int blsSignatureIsEqual(in Signature lhs, in Signature rhs);
        // add
        [DllImport(dllName)] public static extern void blsSecretKeyAdd(ref SecretKey sec, in SecretKey rhs);
        [DllImport(dllName)] public static extern void blsPublicKeyAdd(ref PublicKey pub, in PublicKey rhs);
		[DllImport(dllName)] public static extern void blsSignatureAdd(ref Signature sig, in Signature rhs);
        //	hash buf and set
        [DllImport(dllName)] public static extern int blsHashToSecretKey(ref SecretKey sec, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		/*
			set secretKey if system has /dev/urandom or CryptGenRandom
			return 0 if success else -1
		*/
		[DllImport(dllName)] public static extern int blsSecretKeySetByCSPRNG(ref SecretKey sec);

        [DllImport(dllName)] public static extern void blsGetPublicKey(ref PublicKey pub, in SecretKey sec);
		[DllImport(dllName)] public static extern void blsGetPop(ref Signature sig, in SecretKey sec);

		// return 0 if success
		[DllImport(dllName)] public static extern int blsSecretKeyShare(ref SecretKey sec, in SecretKey msk, ulong k, in Id id);
		[DllImport(dllName)] public static extern int blsPublicKeyShare(ref PublicKey pub, in PublicKey mpk, ulong k, in Id id);


		[DllImport(dllName)] public static extern int blsSecretKeyRecover(ref SecretKey sec, in SecretKey secVec, in Id idVec, ulong n);
		[DllImport(dllName)] public static extern int blsPublicKeyRecover(ref PublicKey pub, in PublicKey pubVec, in Id idVec, ulong n);
		[DllImport(dllName)] public static extern int blsSignatureRecover(ref Signature sig, in Signature sigVec, in Id idVec, ulong n);

		[DllImport(dllName)] public static extern void blsSign(ref Signature sig, in SecretKey sec, [In][MarshalAs(UnmanagedType.LPStr)] string m, ulong size);

		// return 1 if valid
		[DllImport(dllName)] public static extern int blsVerify(in Signature sig, in PublicKey pub, [In][MarshalAs(UnmanagedType.LPStr)] string m, ulong size);
		[DllImport(dllName)] public static extern int blsVerifyPop(in Signature sig, in PublicKey pub);

		//////////////////////////////////////////////////////////////////////////
		// the following apis will be removed

		// mask buf with (1 << (bitLen(r) - 1)) - 1 if buf >= r
		[DllImport(dllName)] public static extern int blsIdSetLittleEndian(ref Id id, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		/*
			return written byte size if success else 0
		*/
		[DllImport(dllName)] public static extern ulong blsIdGetLittleEndian([Out]StringBuilder buf, ulong maxBufSize, in Id id);

		// return 0 if success
		// mask buf with (1 << (bitLen(r) - 1)) - 1 if buf >= r
		[DllImport(dllName)] public static extern int blsSecretKeySetLittleEndian(ref SecretKey sec, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport(dllName)] public static extern int blsSecretKeySetDecStr(ref SecretKey sec, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
        [DllImport(dllName)] public static extern int blsSecretKeySetHexStr(ref SecretKey sec, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
        /*
			return written byte size if success else 0
		*/
        [DllImport(dllName)] public static extern ulong blsSecretKeyGetLittleEndian([Out]StringBuilder buf, ulong maxBufSize, in SecretKey sec);
		/*
			return strlen(buf) if success else 0
			buf is '\0' terminated
		*/
        [DllImport(dllName)] public static extern ulong blsSecretKeyGetDecStr([Out]StringBuilder buf, ulong maxBufSize, in SecretKey sec);
        [DllImport(dllName)] public static extern ulong blsSecretKeyGetHexStr([Out]StringBuilder buf, ulong maxBufSize, in SecretKey sec);
		[DllImport(dllName)] public static extern int blsPublicKeySetHexStr(ref PublicKey pub, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport(dllName)] public static extern ulong blsPublicKeyGetHexStr([Out]StringBuilder buf, ulong maxBufSize, in PublicKey pub);
		[DllImport(dllName)] public static extern int blsSignatureSetHexStr(ref Signature sig, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize);
		[DllImport(dllName)] public static extern ulong blsSignatureGetHexStr([Out]StringBuilder buf, ulong maxBufSize, in Signature sig);

        public static void Init(int curveType = BN254)
		{
			if (!System.Environment.Is64BitProcess) {
				throw new PlatformNotSupportedException("not 64-bit system");
			}
			int err = blsInit(curveType, COMPILED_TIME_VAR);
			if (err != 0) {
				throw new ArgumentException("blsInit");
			}
		}
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct Id {
            private fixed ulong v[ID_UNIT_SIZE];
			public bool IsEqual(in Id rhs)
			{
                return blsIdIsEqual(this, rhs) != 0;
            }
			public void SetDecStr(in String s)
			{
				if (blsIdSetDecStr(ref this, s, (ulong)s.Length) != 0) {
					throw new ArgumentException("blsIdSetDecSt:" + s);
				}
			}
			public void SetHexStr(in String s)
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
				ulong size = blsIdGetDecStr(sb, (ulong)sb.Capacity, this);
				if (size == 0) {
					throw new ArgumentException("blsIdGetDecStr");
				}
				return sb.ToString(0, (int)size);
			}
			public string GetHexStr()
			{
				StringBuilder sb = new StringBuilder(1024);
				ulong size = blsIdGetHexStr(sb, (ulong)sb.Capacity, this);
				if (size == 0) {
					throw new ArgumentException("blsIdGetHexStr");
				}
				return sb.ToString(0, (int)size);
			}
		}
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct SecretKey {
            private fixed ulong v[SECRETKEY_UNIT_SIZE];
			public bool IsEqual(in SecretKey rhs)
			{
				return blsSecretKeyIsEqual(this, rhs) != 0;
			}
			public void SetHexStr(in String s)
			{
				if (blsSecretKeySetHexStr(ref this, s, (ulong)s.Length) != 0) {
					throw new ArgumentException("blsSecretKeySetHexStr:" + s);
				}
			}
			public string GetHexStr()
			{
				StringBuilder sb = new StringBuilder(1024);
				ulong size = blsSecretKeyGetHexStr(sb, (ulong)sb.Capacity, this);
				if (size == 0) {
					throw new ArgumentException("mclBnFr_getStr");
				}
				return sb.ToString(0, (int)size);
			}
			public void Add(in SecretKey rhs)
			{
				blsSecretKeyAdd(ref this, rhs);
			}
			public void SetByCSPRNG()
			{
				blsSecretKeySetByCSPRNG(ref this);
			}
			public void SetHashOf(in string s)
			{
				if (blsHashToSecretKey(ref this, s, (ulong)s.Length) != 0) {
					throw new ArgumentException("blsHashToSecretKey");
				}
			}
            public PublicKey GetPublicKey()
			{
				PublicKey pub = new PublicKey();
				blsGetPublicKey(ref pub, this);
				return pub;
			}
			public Signature Signature(String m)
			{
				Signature Signature = new Signature();
				blsSign(ref Signature, this, m, (ulong)m.Length);
				return Signature;
			}
        }
		// secretKey = sum_{i=0}^{msk.Length - 1} msk[i] * id^i
		public static SecretKey ShareSecretKey(in SecretKey[] msk, in Id id)
		{
			SecretKey sec = new SecretKey();
			if (blsSecretKeyShare(ref sec, msk[0], (ulong)msk.Length, id) != 0) {
				throw new ArgumentException("GetSecretKeyForId:" + id.ToString());
			}
			return sec;
		}
		public static SecretKey RecoverSecretKey(in SecretKey[] secs, in Id[] ids)
		{
			SecretKey sec = new SecretKey();
			if (blsSecretKeyRecover(ref sec, secs[0], ids[0], (ulong)secs.Length) != 0) {
				throw new ArgumentException("Recover");
			}
			return sec;
		}
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct PublicKey {
            private fixed ulong v[PUBLICKEY_UNIT_SIZE];
            public bool IsEqual(in PublicKey rhs)
			{
				return blsPublicKeyIsEqual(this, rhs) != 0;
			}
			public void SetStr(in String s)
			{
				if (blsPublicKeySetHexStr(ref this, s, (ulong)s.Length) != 0) {
					throw new ArgumentException("blsPublicKeySetStr:" + s);
				}
			}
			public string GetHexStr()
			{
				StringBuilder sb = new StringBuilder(1024);
				ulong size = blsPublicKeyGetHexStr(sb, (ulong)sb.Capacity, this);
				if (size == 0) {
					throw new ArgumentException("blsPublicKeyGetStr");
				}
				return sb.ToString(0, (int)size);
			}
			public void Add(in PublicKey rhs)
			{
				blsPublicKeyAdd(ref this, rhs);
			}
			public bool Verify(in Signature sig, in string m)
			{
				return blsVerify(sig, this, m, (ulong)m.Length) == 1;
			}
		}
		// publicKey = sum_{i=0}^{mpk.Length - 1} mpk[i] * id^i
		public static PublicKey SharePublicKey(in PublicKey[] mpk, in Id id)
		{
			PublicKey pub = new PublicKey();
			if (blsPublicKeyShare(ref pub, mpk[0], (ulong)mpk.Length, id) != 0) {
				throw new ArgumentException("GetPublicKeyForId:" + id.ToString());
			}
			return pub;
		}
		public static PublicKey RecoverPublicKey(in PublicKey[] pubs, in Id[] ids)
		{
			PublicKey pub = new PublicKey();
			if (blsPublicKeyRecover(ref pub, pubs[0], ids[0], (ulong)pubs.Length) != 0) {
				throw new ArgumentException("Recover");
			}
			return pub;
		}
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct Signature {
            private fixed ulong v[SIGNATURE_UNIT_SIZE];
            public bool IsEqual(in Signature rhs)
			{
				return blsSignatureIsEqual(this, rhs) != 0;
			}
			public void SetStr(in String s)
			{
				if (blsSignatureSetHexStr(ref this, s, (ulong)s.Length) != 0) {
					throw new ArgumentException("blsSignatureSetStr:" + s);
				}
			}
			public string GetHexStr()
			{
				StringBuilder sb = new StringBuilder(1024);
				ulong size = blsSignatureGetHexStr(sb, (ulong)sb.Capacity, this);
				if (size == 0) {
					throw new ArgumentException("blsSignatureGetStr");
				}
				return sb.ToString(0, (int)size);
			}
			public void Add(in Signature rhs)
			{
				blsSignatureAdd(ref this, rhs);
			}
		}
        public static Signature RecoverSign(in Signature[] signs, in Id[] ids)
		{
			Signature Signature = new Signature();
			if (blsSignatureRecover(ref Signature, signs[0], ids[0], (ulong)signs.Length) != 0) {
				throw new ArgumentException("Recover");
			}
			return Signature;
		}
    }
}
