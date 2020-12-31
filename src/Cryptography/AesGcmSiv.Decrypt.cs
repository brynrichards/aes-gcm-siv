using System;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using Aes = System.Runtime.Intrinsics.X86.Aes;

namespace Cryptography
{
	public unsafe partial class AesGcmSiv
	{
		// DecryptPowersTable decrypts ctLen bytes from ct and writes them to pt. While
		// decrypting, it updates the POLYVAL value in polyval. In order to decrypt and
		// update the POLYVAL value, it uses the expanded key from ks and the table of
		// powers in htbl. Decryption processes 6 blocks of data in parallel.
		private static void DecryptPowersTable(byte* ct, int ctLen, byte* pt, byte* polyval, byte* htbl, byte* tag, byte* ks)
		{
			Vector128<ulong> sCtr1, sCtr2, sCtr3, sCtr4, sCtr5, sCtr6, tmp0, tmp1, tmp2, tmp3, tmp4, h;

			var poly = Vector128.Create(1, 0, 0, 0xc2000000).AsUInt64();
			var t = Sse2.LoadVector128(polyval).AsUInt64();

			var orMask = Vector128.Create(0, 0, 0, 0x80000000).AsByte();
			var ctr = Sse2.Or(Sse2.LoadVector128(tag), orMask);

			var one = Vector128.Create(1, 0, 0, 0);
			var two = Vector128.Create(2, 0, 0, 0);

			int blocks = 0;

			if (ctLen >= 96)
			{
				var ctr1 = ctr;
				var ctr2 = Sse2.Add(ctr.AsInt32(), one).AsByte();
				var ctr3 = Sse2.Add(ctr.AsInt32(), two).AsByte();
				var ctr4 = Sse2.Add(ctr3.AsInt32(), one).AsByte();
				var ctr5 = Sse2.Add(ctr3.AsInt32(), two).AsByte();
				var ctr6 = Sse2.Add(ctr5.AsInt32(), one).AsByte();
				ctr = Sse2.Add(ctr5.AsInt32(), two).AsByte();

				var key = Sse2.LoadVector128(ks);
				ctr1 = Sse2.Xor(ctr1, key);
				ctr2 = Sse2.Xor(ctr2, key);
				ctr3 = Sse2.Xor(ctr3, key);
				ctr4 = Sse2.Xor(ctr4, key);
				ctr5 = Sse2.Xor(ctr5, key);
				ctr6 = Sse2.Xor(ctr6, key);

				for (int i = 1; i < 14; ++i)
				{
					key = Sse2.LoadVector128(&ks[i * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);
				}

				key = Sse2.LoadVector128(&ks[14 * 16]);
				ctr1 = Aes.EncryptLast(ctr1, key);
				ctr2 = Aes.EncryptLast(ctr2, key);
				ctr3 = Aes.EncryptLast(ctr3, key);
				ctr4 = Aes.EncryptLast(ctr4, key);
				ctr5 = Aes.EncryptLast(ctr5, key);
				ctr6 = Aes.EncryptLast(ctr6, key);

				ctr1 = Sse2.Xor(ctr1, Sse2.LoadVector128(&ct[0 * 16]));
				ctr2 = Sse2.Xor(ctr2, Sse2.LoadVector128(&ct[1 * 16]));
				ctr3 = Sse2.Xor(ctr3, Sse2.LoadVector128(&ct[2 * 16]));
				ctr4 = Sse2.Xor(ctr4, Sse2.LoadVector128(&ct[3 * 16]));
				ctr5 = Sse2.Xor(ctr5, Sse2.LoadVector128(&ct[4 * 16]));
				ctr6 = Sse2.Xor(ctr6, Sse2.LoadVector128(&ct[5 * 16]));

				Sse2.Store(&pt[0 * 16], ctr1);
				Sse2.Store(&pt[1 * 16], ctr2);
				Sse2.Store(&pt[2 * 16], ctr3);
				Sse2.Store(&pt[3 * 16], ctr4);
				Sse2.Store(&pt[4 * 16], ctr5);
				Sse2.Store(&pt[5 * 16], ctr6);

				ctLen -= 96;
				blocks += 6;

				while (ctLen >= 96)
				{
					sCtr6 = ctr6.AsUInt64();
					sCtr5 = ctr5.AsUInt64();
					sCtr4 = ctr4.AsUInt64();
					sCtr3 = ctr3.AsUInt64();
					sCtr2 = ctr2.AsUInt64();
					sCtr1 = ctr1.AsUInt64();

					ctr1 = ctr;
					ctr2 = Sse2.Add(ctr.AsInt32(), one).AsByte();
					ctr3 = Sse2.Add(ctr.AsInt32(), two).AsByte();
					ctr4 = Sse2.Add(ctr3.AsInt32(), one).AsByte();
					ctr5 = Sse2.Add(ctr3.AsInt32(), two).AsByte();
					ctr6 = Sse2.Add(ctr5.AsInt32(), one).AsByte();
					ctr = Sse2.Add(ctr5.AsInt32(), two).AsByte();

					key = Sse2.LoadVector128(ks);
					ctr1 = Sse2.Xor(ctr1, key);
					ctr2 = Sse2.Xor(ctr2, key);
					ctr3 = Sse2.Xor(ctr3, key);
					ctr4 = Sse2.Xor(ctr4, key);
					ctr5 = Sse2.Xor(ctr5, key);
					ctr6 = Sse2.Xor(ctr6, key);

					tmp3 = Sse2.LoadVector128(htbl).AsUInt64();
					tmp1 = Pclmulqdq.CarrylessMultiply(sCtr6, tmp3, 0x11);
					tmp2 = Pclmulqdq.CarrylessMultiply(sCtr6, tmp3, 0x00);
					tmp0 = Pclmulqdq.CarrylessMultiply(sCtr6, tmp3, 0x01);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr6, tmp3, 0x10);
					tmp0 = Sse2.Xor(tmp3, tmp0);

					key = Sse2.LoadVector128(&ks[1 * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);

					h = Sse2.LoadVector128(&htbl[1 * 16]).AsUInt64();
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr5, h, 0x10);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr5, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr5, h, 0x00);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr5, h, 0x01);
					tmp0 = Sse2.Xor(tmp0, tmp3);

					key = Sse2.LoadVector128(&ks[2 * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);

					h = Sse2.LoadVector128(&htbl[2 * 16]).AsUInt64();
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr4, h, 0x10);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr4, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr4, h, 0x00);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr4, h, 0x01);
					tmp0 = Sse2.Xor(tmp0, tmp3);

					key = Sse2.LoadVector128(&ks[3 * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);

					h = Sse2.LoadVector128(&htbl[3 * 16]).AsUInt64();
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr3, h, 0x10);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr3, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr3, h, 0x00);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr3, h, 0x01);
					tmp0 = Sse2.Xor(tmp0, tmp3);

					key = Sse2.LoadVector128(&ks[4 * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);

					h = Sse2.LoadVector128(&htbl[4 * 16]).AsUInt64();
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr2, h, 0x10);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr2, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr2, h, 0x00);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr2, h, 0x01);
					tmp0 = Sse2.Xor(tmp0, tmp3);

					key = Sse2.LoadVector128(&ks[5 * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);

					key = Sse2.LoadVector128(&ks[6 * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);

					key = Sse2.LoadVector128(&ks[7 * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);

					sCtr1 = Sse2.Xor(t, sCtr1);
					tmp4 = Sse2.LoadVector128(&htbl[5 * 16]).AsUInt64();
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr1, tmp4, 0x01);
					tmp0 = Sse2.Xor(tmp3, tmp0);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr1, tmp4, 0x11);
					tmp1 = Sse2.Xor(tmp3, tmp1);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr1, tmp4, 0x00);
					tmp2 = Sse2.Xor(tmp3, tmp2);
					tmp3 = Pclmulqdq.CarrylessMultiply(sCtr1, tmp4, 0x10);
					tmp0 = Sse2.Xor(tmp3, tmp0);

					key = Sse2.LoadVector128(&ks[8 * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);

					tmp3 = Sse2.ShiftRightLogical128BitLane(tmp0, 8);
					tmp4 = Sse2.Xor(tmp3, tmp1);
					tmp3 = Sse2.ShiftLeftLogical128BitLane(tmp0, 8);
					t = Sse2.Xor(tmp3, tmp2);

					key = Sse2.LoadVector128(&ks[9 * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);

					tmp1 = Ssse3.AlignRight(t.AsSByte(), t.AsSByte(), 8).AsUInt64();
					t = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
					t = Sse2.Xor(tmp1, t);

					key = Sse2.LoadVector128(&ks[10 * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);

					key = Sse2.LoadVector128(&ks[11 * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);

					key = Sse2.LoadVector128(&ks[12 * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);

					key = Sse2.LoadVector128(&ks[13 * 16]);
					ctr1 = Aes.Encrypt(ctr1, key);
					ctr2 = Aes.Encrypt(ctr2, key);
					ctr3 = Aes.Encrypt(ctr3, key);
					ctr4 = Aes.Encrypt(ctr4, key);
					ctr5 = Aes.Encrypt(ctr5, key);
					ctr6 = Aes.Encrypt(ctr6, key);

					key = Sse2.LoadVector128(&ks[14 * 16]);
					ctr1 = Aes.EncryptLast(ctr1, key);
					ctr2 = Aes.EncryptLast(ctr2, key);
					ctr3 = Aes.EncryptLast(ctr3, key);
					ctr4 = Aes.EncryptLast(ctr4, key);
					ctr5 = Aes.EncryptLast(ctr5, key);
					ctr6 = Aes.EncryptLast(ctr6, key);

					ctr1 = Sse2.Xor(ctr1, Sse2.LoadVector128(&ct[(blocks + 0) * 16]));
					ctr2 = Sse2.Xor(ctr2, Sse2.LoadVector128(&ct[(blocks + 1) * 16]));
					ctr3 = Sse2.Xor(ctr3, Sse2.LoadVector128(&ct[(blocks + 2) * 16]));
					ctr4 = Sse2.Xor(ctr4, Sse2.LoadVector128(&ct[(blocks + 3) * 16]));
					ctr5 = Sse2.Xor(ctr5, Sse2.LoadVector128(&ct[(blocks + 4) * 16]));
					ctr6 = Sse2.Xor(ctr6, Sse2.LoadVector128(&ct[(blocks + 5) * 16]));

					tmp1 = Ssse3.AlignRight(t.AsSByte(), t.AsSByte(), 8).AsUInt64();
					t = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
					t = Sse2.Xor(tmp1, t);
					t = Sse2.Xor(tmp4, t);

					Sse2.Store(&pt[(blocks + 0) * 16], ctr1);
					Sse2.Store(&pt[(blocks + 1) * 16], ctr2);
					Sse2.Store(&pt[(blocks + 2) * 16], ctr3);
					Sse2.Store(&pt[(blocks + 3) * 16], ctr4);
					Sse2.Store(&pt[(blocks + 4) * 16], ctr5);
					Sse2.Store(&pt[(blocks + 5) * 16], ctr6);

					ctLen -= 96;
					blocks += 6;
				}

				sCtr6 = ctr6.AsUInt64();
				sCtr5 = ctr5.AsUInt64();
				sCtr4 = ctr4.AsUInt64();
				sCtr3 = ctr3.AsUInt64();
				sCtr2 = ctr2.AsUInt64();
				sCtr1 = ctr1.AsUInt64();

				tmp3 = Sse2.LoadVector128(htbl).AsUInt64();
				tmp0 = Pclmulqdq.CarrylessMultiply(sCtr6, tmp3, 0x10);
				tmp1 = Pclmulqdq.CarrylessMultiply(sCtr6, tmp3, 0x11);
				tmp2 = Pclmulqdq.CarrylessMultiply(sCtr6, tmp3, 0x00);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr6, tmp3, 0x01);
				tmp0 = Sse2.Xor(tmp3, tmp0);

				h = Sse2.LoadVector128(&htbl[1 * 16]).AsUInt64();
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr5, h, 0x10);
				tmp0 = Sse2.Xor(tmp0, tmp3);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr5, h, 0x11);
				tmp1 = Sse2.Xor(tmp1, tmp3);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr5, h, 0x00);
				tmp2 = Sse2.Xor(tmp2, tmp3);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr5, h, 0x01);
				tmp0 = Sse2.Xor(tmp0, tmp3);

				h = Sse2.LoadVector128(&htbl[2 * 16]).AsUInt64();
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr4, h, 0x10);
				tmp0 = Sse2.Xor(tmp0, tmp3);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr4, h, 0x11);
				tmp1 = Sse2.Xor(tmp1, tmp3);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr4, h, 0x00);
				tmp2 = Sse2.Xor(tmp2, tmp3);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr4, h, 0x01);
				tmp0 = Sse2.Xor(tmp0, tmp3);

				h = Sse2.LoadVector128(&htbl[3 * 16]).AsUInt64();
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr3, h, 0x10);
				tmp0 = Sse2.Xor(tmp0, tmp3);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr3, h, 0x11);
				tmp1 = Sse2.Xor(tmp1, tmp3);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr3, h, 0x00);
				tmp2 = Sse2.Xor(tmp2, tmp3);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr3, h, 0x01);
				tmp0 = Sse2.Xor(tmp0, tmp3);

				h = Sse2.LoadVector128(&htbl[4 * 16]).AsUInt64();
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr2, h, 0x10);
				tmp0 = Sse2.Xor(tmp0, tmp3);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr2, h, 0x11);
				tmp1 = Sse2.Xor(tmp1, tmp3);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr2, h, 0x00);
				tmp2 = Sse2.Xor(tmp2, tmp3);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr2, h, 0x01);
				tmp0 = Sse2.Xor(tmp0, tmp3);

				sCtr1 = Sse2.Xor(t, sCtr1);
				tmp4 = Sse2.LoadVector128(&htbl[5 * 16]).AsUInt64();
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr1, tmp4, 0x11);
				tmp1 = Sse2.Xor(tmp3, tmp1);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr1, tmp4, 0x00);
				tmp2 = Sse2.Xor(tmp3, tmp2);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr1, tmp4, 0x10);
				tmp0 = Sse2.Xor(tmp3, tmp0);
				tmp3 = Pclmulqdq.CarrylessMultiply(sCtr1, tmp4, 0x01);
				tmp0 = Sse2.Xor(tmp3, tmp0);

				tmp3 = Sse2.ShiftRightLogical128BitLane(tmp0, 8);
				tmp4 = Sse2.Xor(tmp3, tmp1);
				tmp3 = Sse2.ShiftLeftLogical128BitLane(tmp0, 8);
				t = Sse2.Xor(tmp3, tmp2);

				tmp1 = Ssse3.AlignRight(t.AsSByte(), t.AsSByte(), 8).AsUInt64();
				t = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
				t = Sse2.Xor(tmp1, t);
				tmp1 = Ssse3.AlignRight(t.AsSByte(), t.AsSByte(), 8).AsUInt64();
				t = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
				t = Sse2.Xor(tmp1, t);
				t = Sse2.Xor(tmp4, t);
			}

			h = Sse2.LoadVector128(htbl).AsUInt64();

			while (ctLen >= 16)
			{
				var tmp = ctr;
				ctr = Sse2.Add(ctr.AsInt32(), one).AsByte();
				tmp = Sse2.Xor(tmp, Sse2.LoadVector128(ks));

				for (int i = 1; i < 14; ++i)
				{
					tmp = Aes.Encrypt(tmp, Sse2.LoadVector128(&ks[i * 16]));
				}

				tmp = Aes.EncryptLast(tmp, Sse2.LoadVector128(&ks[14 * 16]));
				tmp = Sse2.Xor(tmp, Sse2.LoadVector128(&ct[blocks * 16]));
				Sse2.Store(&pt[blocks * 16], tmp);

				t = Sse2.Xor(tmp.AsUInt64(), t);
				tmp1 = Pclmulqdq.CarrylessMultiply(t, h, 0x00);
				tmp4 = Pclmulqdq.CarrylessMultiply(t, h, 0x11);
				tmp2 = Pclmulqdq.CarrylessMultiply(t, h, 0x10);
				tmp3 = Pclmulqdq.CarrylessMultiply(t, h, 0x01);
				tmp2 = Sse2.Xor(tmp3, tmp2);
				tmp3 = Sse2.ShiftLeftLogical128BitLane(tmp2, 8);
				tmp2 = Sse2.ShiftRightLogical128BitLane(tmp2, 8);
				tmp1 = Sse2.Xor(tmp1, tmp3);
				tmp4 = Sse2.Xor(tmp2, tmp4);

				tmp2 = Pclmulqdq.CarrylessMultiply(tmp1, poly, 0x10);
				tmp3 = Sse2.Shuffle(tmp1.AsUInt32(), 78).AsUInt64();
				tmp1 = Sse2.Xor(tmp2, tmp3);
				tmp2 = Pclmulqdq.CarrylessMultiply(tmp1, poly, 0x10);
				tmp3 = Sse2.Shuffle(tmp1.AsUInt32(), 78).AsUInt64();
				tmp1 = Sse2.Xor(tmp2, tmp3);
				t = Sse2.Xor(tmp1, tmp4);

				ctLen -= 16;
				++blocks;
			}

			if (ctLen > 0)
			{
				byte* b = stackalloc byte[16];
				new Span<byte>(ct + blocks * 16, ctLen).CopyTo(new Span<byte>(b, 16));
				var tmp = Sse2.Xor(ctr, Sse2.LoadVector128(ks));

				for (int i = 1; i < 14; ++i)
				{
					tmp = Aes.Encrypt(tmp, Sse2.LoadVector128(&ks[i * 16]));
				}

				tmp = Aes.EncryptLast(tmp, Sse2.LoadVector128(&ks[14 * 16]));
				tmp = Sse2.Xor(tmp, Sse2.LoadVector128(b));
				Sse2.Store(b, tmp);

				new Span<byte>(b, ctLen).CopyTo(new Span<byte>(&pt[blocks * 16], ctLen));
				new Span<byte>(b + ctLen, 16 - ctLen).Clear();

				t = Sse2.Xor(Sse2.LoadVector128(b).AsUInt64(), t);
				tmp1 = Pclmulqdq.CarrylessMultiply(t, h, 0x00);
				tmp4 = Pclmulqdq.CarrylessMultiply(t, h, 0x11);
				tmp2 = Pclmulqdq.CarrylessMultiply(t, h, 0x10);
				tmp3 = Pclmulqdq.CarrylessMultiply(t, h, 0x01);
				tmp2 = Sse2.Xor(tmp3, tmp2);
				tmp3 = Sse2.ShiftLeftLogical128BitLane(tmp2, 8);
				tmp2 = Sse2.ShiftRightLogical128BitLane(tmp2, 8);
				tmp1 = Sse2.Xor(tmp1, tmp3);
				tmp4 = Sse2.Xor(tmp2, tmp4);

				tmp2 = Pclmulqdq.CarrylessMultiply(tmp1, poly, 0x10);
				tmp3 = Sse2.Shuffle(tmp1.AsUInt32(), 78).AsUInt64();
				tmp1 = Sse2.Xor(tmp2, tmp3);
				tmp2 = Pclmulqdq.CarrylessMultiply(tmp1, poly, 0x10);
				tmp3 = Sse2.Shuffle(tmp1.AsUInt32(), 78).AsUInt64();
				tmp1 = Sse2.Xor(tmp2, tmp3);
				t = Sse2.Xor(tmp1, tmp4);
			}

			Sse2.Store(polyval, t.AsByte());
		}
	}
}
