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
		public static extern void blsSecretKeySign(ref SecretKey sec, ref Sign sign, [In][MarshalAs(UnmanagedType.LPStr)] string m, ulong size);
		[DllImport("bls256.dll")]
		public static extern int blsSecretKeySet(ref SecretKey sec, ref SecretKey msk, ulong k, ref Id id);
		[DllImport("bls256.dll")]
		public static extern int blsSecretKeyRecover(ref SecretKey sec, ref SecretKey secVec, ref Id idVec, ulong n);
		[DllImport("bls256.dll")]
		public static extern void blsSecretKeyGetPop(ref SecretKey sec, ref Sign sign);
		[DllImport("bls256.dll")]
		public static extern int blsPublicKeyIsSame(ref PublicKey lhs, ref PublicKey rhs);
		[DllImport("bls256.dll")]
		public static extern void blsPublicKeyPut(ref PublicKey pub);
		[DllImport("bls256.dll")]
		public static extern void blsPublicKeyCopy(ref PublicKey dst, ref PublicKey src);
		[DllImport("bls256.dll")]
		public static extern int blsPublicKeySetStr(ref PublicKey pub, ref byte buf, int bufSize, int ioMode);
		[DllImport("bls256.dll")]
		public static extern ulong blsPublicKeyGetStr(ref PublicKey pub, ref byte buf, int maxBufSize, int ioMode);
		[DllImport("bls256.dll")]
		public static extern void blsPublicKeyAdd(ref PublicKey pub, ref PublicKey rhs);
		[DllImport("bls256.dll")]
		public static extern int blsPublicKeySet(ref PublicKey pub, ref PublicKey mpk, ulong k, ref Id id);
		[DllImport("bls256.dll")]
		public static extern int blsPublicKeyRecover(ref PublicKey pub, ref PublicKey pubVec, ref Id idVec, ulong n);
		[DllImport("bls256.dll")]
		public static extern int blsSignIsSame(ref Sign lhs, ref Sign rhs);
		[DllImport("bls256.dll")]
		public static extern int blsSignSetStr(ref Sign sign, ref byte buf, int bufSize, int ioMode);
		[DllImport("bls256.dll")]
		public static extern ulong blsSignGetStr(ref Sign sign, ref byte buf, int maxBufSize, int ioMode);
		[DllImport("bls256.dll")]
		public static extern void blsSignAdd(ref Sign sign, ref Sign rhs);
		[DllImport("bls256.dll")]
		public static extern int blsSignRecover(ref Sign sign, ref Sign signVec, ref Id idVec, ulong n);
		[DllImport("bls256.dll")]
		public static extern int blsSignVerify(ref Sign sign, ref PublicKey pub, [In][MarshalAs(UnmanagedType.LPStr)] string m, ulong size);
		[DllImport("bls256.dll")]
		public static extern int blsSignVerifyPop(ref Sign sign, ref PublicKey pub);

		static string ConvertByteToHexStr(byte[] b, int size)
		{
			String s = "";
			for (int i = 0; i < size; i++) {
				s += Buffer.GetByte(b, i).ToString("x2");
			}
			return s;
		}
		static byte[] ConvertHexStrToByte(string s)
		{
			if ((s.Length & 1) == 1) {
				throw new ArgumentException("ConvertHexStrToByte odd length");
			}
			int n = s.Length / 2;
			byte[] b = new byte[n];
			for (int i = 0; i < n; i++) {
				int x = Convert.ToInt32(s.Substring(i * 2, 2), 16);
				b[i] = (byte)x;
			}
			return b;
		}


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
			public bool IsSame(Id rhs)
			{
				return blsIdIsSame(ref this, ref rhs) != 0;
			}
			public void SetStr(String s, int ioMode)
			{
				if (blsIdSetStr(ref this, s, (ulong)s.Length, ioMode) != 0) {
					throw new ArgumentException("blsIdSetStr:" + s);
				}
			}
			public void SetInt(int x)
			{
				v0 = (uint)x;
				v1 = v2 = v3 = 0;
			}
			public string GetStr(int ioMode)
			{
				StringBuilder sb = new StringBuilder(1024);
				ulong size = blsIdGetStr(ref this, sb, (ulong)sb.Capacity, ioMode);
				if (size == 0) {
					throw new ArgumentException("blsIdGetStr");
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
					throw new ArgumentException("SetArray:" + n.ToString());
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
					throw new ArgumentException("blsSecretKeySetStr:" + s);
				}
			}
			public string GetStr(int ioMode)
			{
				StringBuilder sb = new StringBuilder(1024);
				ulong size = blsSecretKeyGetStr(ref this, sb, (ulong)sb.Capacity, ioMode);
				if (size == 0) {
					throw new ArgumentException("blsSecretKeyGetStr");
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
					throw new ArgumentException("SetArray:" + n.ToString());
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
			public Sign Sign(String m)
			{
				Sign sign = new Sign();
				blsSecretKeySign(ref this, ref sign, m, (ulong)m.Length);
				return sign;
			}
		}
		// secretKey = sum_{i=0}^{msk.Length - 1} msk[i] * id^i
		public static SecretKey ShareSecretKey(SecretKey[] msk, Id id)
		{
			SecretKey sec = new SecretKey();
			if (blsSecretKeySet(ref sec, ref msk[0], (ulong)msk.Length, ref id) != 0) {
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
			public bool IsSame(PublicKey rhs)
			{
				return blsPublicKeyIsSame(ref this, ref rhs) != 0;
			}
			public void SetStr(String s)
			{
				byte[] b = ConvertHexStrToByte(s);
				if (blsPublicKeySetStr(ref this, ref b[0], b.Length, IoEcComp) != 0) {
					throw new ArgumentException("blsPublicKeySetStr:" + s);
				}
			}
			public override string ToString()
			{
				byte[] b = new byte[1024];
				int size = (int)blsPublicKeyGetStr(ref this, ref b[0], b.Length, IoEcComp);
				if (size == 0) {
					throw new ArgumentException("blsPublicKeyGetStr");
				}
				return ConvertByteToHexStr(b, size);
			}
			public void Add(PublicKey rhs)
			{
				blsPublicKeyAdd(ref this, ref rhs);
			}
		}
		// publicKey = sum_{i=0}^{mpk.Length - 1} mpk[i] * id^i
		public static PublicKey SharePublicKey(PublicKey[] mpk, Id id)
		{
			PublicKey pub = new PublicKey();
			if (blsPublicKeySet(ref pub, ref mpk[0], (ulong)mpk.Length, ref id) != 0) {
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
		public struct Sign {
			private ulong v00, v01, v02, v03, v04, v05, v06, v07, v08, v09, v10, v11;
			public bool IsSame(Sign rhs)
			{
				return blsSignIsSame(ref this, ref rhs) != 0;
			}
			public void SetStr(String s)
			{
				byte[] b = ConvertHexStrToByte(s);
				if (blsSignSetStr(ref this, ref b[0], b.Length, IoEcComp) != 0) {
					throw new ArgumentException("blsSignSetStr:" + s);
				}
			}
			public override string ToString()
			{
				byte[] b = new byte[1024];
				int size = (int)blsSignGetStr(ref this, ref b[0], b.Length, IoEcComp);
				if (size == 0) {
					throw new ArgumentException("blsSignGetStr");
				}
				return ConvertByteToHexStr(b, size);
			}
			public void Add(Sign rhs)
			{
				blsSignAdd(ref this, ref rhs);
			}
			public bool Verify(PublicKey pub, string m)
			{
				return blsSignVerify(ref this, ref pub, m, (ulong)m.Length) == 1;
			}
		}
		public static Sign RecoverSign(Sign[] signs, Id[] ids)
		{
			Sign sign = new Sign();
			if (blsSignRecover(ref sign, ref signs[0], ref ids[0], (ulong)signs.Length) != 0) {
				throw new ArgumentException("Recover");
			}
			return sign;
		}
	}
}
