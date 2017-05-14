þ½Ž¿using System;
using System.Text;
using System.Runtime.InteropServices;

namespace mcl {
	class BLS256 {
		const int IoEcComp = 512; // fixed byte representation
		public const int maxUnitSize = 4;
		[DllImport("bls256.dll")]
		public static extern int blsInit(int curve, int maxUnitSize);
		[DllImport("bls256.dll")]
		public static extern int blsIdIsSame(ref Id lhs, ref Id rhs);

		[DllImport("bls256.dll")]
		public static extern int blsIdSetStr(ref Id id, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize, int ioMode);
		[DllImport("bls256.dll")]
		public static extern ulong blsIdGetStr(ref Id id, [Out]StringBuilder buf, ulong maxBufSize, int ioMode);
		[DllImport("bls256.dll")]
		public static extern void blsIdSet(ref Id id, ref ulong p);
		[DllImport("bls256.dll")]
		public static extern int blsSecretKeyIsSame(ref SecretKey lhs, ref SecretKey rhs);
		[DllImport("bls256.dll")]
		public static extern void blsSecretKeySetArray(ref SecretKey sec, ref ulong p);
		[DllImport("bls256.dll")]
		public static extern int blsSecretKeySetStr(ref SecretKey sec, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize, int ioMode);
		[DllImport("bls256.dll")]
		public static extern ulong blsSecretKeyGetStr(ref SecretKey sec, [Out]StringBuilder buf, ulong maxBufSize, int ioMode);
		[DllImport("bls256.dll")]
		public static extern void blsSecretKeyAdd(ref SecretKey sec, ref SecretKey rhs);
		[DllImport("bls256.dll")]
		public static extern void blsSecretKeyInit(ref SecretKey sec);
		[DllImport("bls256.dll")]
		public static extern void blsSecretKeyGetPublicKey(ref SecretKey sec, ref PublicKey pub);
		[DllImport("bls256.dll")]
		public static extern void blsSecretKeySign(ref SecretKey sec, ref Signature sign, [In][MarshalAs(UnmanagedType.LPStr)] string m, ulong size);
		[DllImport("bls256.dll")]
		public static extern int blsSecretKeySet(ref SecretKey sec, ref SecretKey msk, ulong k, ref Id id);
		[DllImport("bls256.dll")]
		public static extern int blsSecretKeyRecover(ref SecretKey sec, ref SecretKey secVec, ref Id idVec, ulong n);
		[DllImport("bls256.dll")]
		public static extern void blsSecretKeyGetPop(ref SecretKey sec, ref Signature sign);
		[DllImport("bls256.dll")]
		public static extern int blsPublicKeyIsSame(ref PublicKey lhs, ref PublicKey rhs);
		[DllImport("bls256.dll")]
		public static extern void blsPublicKeyPut(ref PublicKey pub);
		[DllImport("bls256.dll")]
		public static extern void blsPublicKeyCopy(ref PublicKey dst, ref PublicKey src);
		[DllImport("bls256.dll")]
		public static extern int blsPublicKeySetStr(ref PublicKey pub, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize, int ioMode);
		[DllImport("bls256.dll")]
		public static extern ulong blsPublicKeyGetStr(ref PublicKey pub, [Out]StringBuilder buf, ulong maxBufSize, int ioMode);
		[DllImport("bls256.dll")]
		public static extern void blsPublicKeyAdd(ref PublicKey pub, ref PublicKey rhs);
		[DllImport("bls256.dll")]
		public static extern int blsPublicKeySet(ref PublicKey pub, ref PublicKey mpk, ulong k, ref Id id);
		[DllImport("bls256.dll")]
		public static extern int blsPublicKeyRecover(ref PublicKey pub, ref PublicKey pubVec, ref Id idVec, ulong n);
		[DllImport("bls256.dll")]
		public static extern int blsSignIsSame(ref Signature lhs, ref Signature rhs);
		[DllImport("bls256.dll")]
		public static extern void blsSignPut(ref Signature sign);
		[DllImport("bls256.dll")]
		public static extern void blsSignCopy(ref Signature dst, ref Signature src);
		[DllImport("bls256.dll")]
		public static extern int blsSignSetStr(ref Signature sign, [In][MarshalAs(UnmanagedType.LPStr)] string buf, ulong bufSize, int ioMode);
		[DllImport("bls256.dll")]
		public static extern ulong blsSignGetStr(ref Signature sign, [Out]StringBuilder buf, ulong maxBufSize, int ioMode);
		[DllImport("bls256.dll")]
		public static extern void blsSignAdd(ref Signature sign, ref Signature rhs);
		[DllImport("bls256.dll")]
		public static extern int blsSignRecover(ref Signature sign, ref Signature signVec, ref Id idVec, ulong n);
		[DllImport("bls256.dll")]
		public static extern int blsSignVerify(ref Signature sign, ref PublicKey pub, [In][MarshalAs(UnmanagedType.LPStr)] string m, ulong size);
		[DllImport("bls256.dll")]
		public static extern int blsSignVerifyPop(ref Signature sign, ref PublicKey pub);

		public static void Init()
		{
			const int CurveFp254BNb = 0;
			if (!System.Environment.Is64BitProcess) {
				throw new PlatformNotSupportedException("not 64-bit system");
			}
			int err = blsInit(CurveFp254BNb, maxUnitSize);
			if (err != 0) {
				throw new InvalidOperationException("blsInit");
			}
		}

		public struct Id {
			private ulong v0, v1, v2, v3;
			public bool IsSame(Id rhs)
			{
				return blsIdIsSame(ref this, ref rhs) != 0;
			}
			public void SetStr(String s, int ioMode)
			{
				if (blsIdSetStr(ref this, s, (ulong)s.Length, ioMode) != 0) {
					throw new InvalidOperationException("blsIdSetStr:" + s);
				}
			}
			public string GetStr(int ioMode)
			{
				StringBuilder sb = new StringBuilder(1024);
				ulong size = blsIdGetStr(ref this, sb, (ulong)sb.Capacity + 1, ioMode);
				if (size == 0) {
					throw new InvalidOperationException("blsIdGetStr");
				}
				return sb.ToString(0, (int)size);
			}
			public override string ToString()
			{
				return GetStr(16);
			}
			public void SetArray(ulong[] p)
			{
				int n = p.Length;
				if (n != maxUnitSize) {
					throw new InvalidOperationException("SetArray:" + n.ToString());
				}
				blsIdSet(ref this, ref p[0]);
			}
		}
		public struct SecretKey {
			private ulong v0, v1, v2, v3;
			public bool IsSame(SecretKey rhs)
			{
				return blsSecretKeyIsSame(ref this, ref rhs) != 0;
			}
			public void SetStr(String s, int ioMode)
			{
				if (blsSecretKeySetStr(ref this, s, (ulong)s.Length, ioMode) != 0) {
					throw new InvalidOperationException("blsSecretKeySetStr:" + s);
				}
			}
			public string GetStr(int ioMode)
			{
				StringBuilder sb = new StringBuilder(1024);
				ulong size = blsSecretKeyGetStr(ref this, sb, (ulong)sb.Capacity + 1, ioMode);
				if (size == 0) {
					throw new InvalidOperationException("blsSecretKeyGetStr");
				}
				return sb.ToString(0, (int)size);
			}
			public override string ToString()
			{
				return GetStr(16);
			}
			public void SetArray(ulong[] p)
			{
				int n = p.Length;
				if (n != maxUnitSize) {
					throw new InvalidOperationException("SetArray:" + n.ToString());
				}
				blsSecretKeySetArray(ref this, ref p[0]);
			}
			public void Add(SecretKey rhs)
			{
				blsSecretKeyAdd(ref this, ref rhs);
			}
			public void Init()
			{
				blsSecretKeyInit(ref this);
			}
			public PublicKey GetPublicKey()
			{
				PublicKey pub = new PublicKey();
				blsSecretKeyGetPublicKey(ref this, ref pub);
				return pub;
			}
			public Signature Sign(String m)
			{
				Signature sign = new Signature();
				blsSecretKeySign(ref this, ref sign, m, (ulong)m.Length);
				return sign;
			}
			// secretKey = sum_{i=0}^{msk.Length - 1} msk[i] * id^i
			public void ShareById(SecretKey[] msk, Id id)
			{
				if (blsSecretKeySet(ref this, ref msk[0], (ulong)msk.Length, ref id) != 0) {
					throw new InvalidOperationException("GetSecretKeyForId:" + id.ToString());
				}
			}
		}
		public struct Signature {
			private ulong v00, v01, v02, v03, v04, v05, v06, v07, v08, v09, v10, v11;
		}
		public struct PublicKey {
			private ulong v00, v01, v02, v03, v04, v05, v06, v07, v08, v09, v10, v11;
			private ulong v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23;
		}
	}
}
