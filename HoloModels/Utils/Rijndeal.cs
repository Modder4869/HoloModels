//https://github.com/Razmoth/HOMEManager/blob/master/HOMEManager/Utils/Rijndeal.cs
namespace Utils
{
    /// <summary>
	/// AUTHOR:       Phil Fresle
	/// COPYRIGHT:    Copyright 2001-2005 Phil Fresle
	/// EMAIL:        phil@frez.co.uk
	/// WEB:          http://www.frez.co.uk
	/// Implementation of the AES Rijndael Block Cipher, converted from my VB6 version. 
	/// Inspired by Mike Scott's implementation in C. Permission for free direct or 
	/// derivative use is granted subject to compliance with any conditions that the 
	/// originators of the algorithm place on its exploitation.
	/// 
	/// The Rijndael home page is here:-
	/// http://www.iaik.tu-graz.ac.at/research/krypto/AES/old/~rijmen/rijndael/
	/// 
	/// NOTE: All string conversions assume strings are Unicode; this may yield different
	/// results from other implementations if the other implementations are based 
	/// on Ascii strings. Unicode is a 2-byte character set, and means that the routines
	/// will work just fine on, for instance, Japanese text.
	/// 
	/// MODIFICATION HISTORY:
	/// 16-Feb-2001		Phil Fresle		Initial VB6 Version
	/// 03-Apr-2001		Phil Fresle     Added EncryptData and DecryptData functions to 
	///									VB6 version.
	/// 19-Apr-2001		Phil Fresle     Thanks to Paolo Migliaccio for finding a bug
	///									with 256 bit key in VB6 version.
	///	11-Jul-2005		Phil Fresle		Initial C# version.
	/// </summary>
	/// 
    public static class Rijndael
    {
        public enum BlockSize { Block128, Block192, Block256 };
        public enum KeySize { Key128, Key192, Key256 };
        public enum EncryptionMode { ModeECB, ModeCBC };

        private static byte[] InCo = { 0xB, 0xD, 0x9, 0xE };
        private static byte[] fbsub = new byte[256];
        private static byte[] rbsub = new byte[256];
        private static byte[] ptab = new byte[256];
        private static byte[] ltab = new byte[256];
        private static uint[] ftable = new uint[256];
        private static uint[] rtable = new uint[256];
        private static uint[] rco = new uint[30];
        private static int Nk, Nb, Nr;
        private static byte[] fi = new byte[24];
        private static byte[] ri = new byte[24];
        private static uint[] fkey = new uint[120];
        private static uint[] rkey = new uint[120];

        private static byte RotateLeft(byte valueToShift, int shiftBits)
        {
            // Rotate the bits in the byte
            return (byte)((valueToShift << shiftBits) |
                (valueToShift >> (8 - shiftBits)));
        }

        private static uint RotateLeft(uint valueToShift, int shiftBits)
        {
            // Rotate the bits in the integer
            return (valueToShift << shiftBits) |
                (valueToShift >> (32 - shiftBits));
        }

        private static uint Pack(byte[] b)
        {
            uint temp = 0;

            for (byte i = 0; i <= 3; i++)
                temp |= ((uint)b[i] << (i * 8));

            return temp;
        }

        private static uint PackFrom(byte[] b, int k)
        {
            uint temp = 0;

            for (byte i = 0; i <= 3; i++)
                temp |= ((uint)b[i + k] << (i * 8));

            return temp;
        }

        private static void Unpack(uint a, byte[] b)
        {
            b[0] = (byte)a;
            b[1] = (byte)(a >> 8);
            b[2] = (byte)(a >> 16);
            b[3] = (byte)(a >> 24);
        }

        private static void UnpackFrom(uint a, byte[] b, int k)
        {
            b[0 + k] = (byte)a;
            b[1 + k] = (byte)(a >> 8);
            b[2 + k] = (byte)(a >> 16);
            b[3 + k] = (byte)(a >> 24);
        }

        private static byte xtime(byte a)
        {
            byte b;

            if ((a & 0x80) != 0)
                b = 0x1b;
            else
                b = 0;

            a <<= 1;
            a ^= b;

            return a;
        }

        private static byte bmul(byte x, byte y)
        {
            if (x != 0 && y != 0)
                return ptab[(ltab[x] + ltab[y]) % 255];
            else
                return 0;
        }

        private static uint SubByte(uint a)
        {
            byte[] b = new byte[4];

            Unpack(a, b);
            b[0] = fbsub[b[0]];
            b[1] = fbsub[b[1]];
            b[2] = fbsub[b[2]];
            b[3] = fbsub[b[3]];

            return Pack(b);
        }

        private static byte product(uint x, uint y)
        {
            byte[] xb = new byte[4];
            byte[] yb = new byte[4];

            Unpack(x, xb);
            Unpack(y, yb);

            return (byte)(bmul(xb[0], yb[0]) ^ bmul(xb[1], yb[1]) ^
                bmul(xb[2], yb[2]) ^ bmul(xb[3], yb[3]));
        }

        private static uint InvMixCol(uint x)
        {
            uint y, m;
            byte[] b = new byte[4];

            m = Pack(InCo);
            b[3] = product(m, x);
            m = RotateLeft(m, 24);
            b[2] = product(m, x);
            m = RotateLeft(m, 24);
            b[1] = product(m, x);
            m = RotateLeft(m, 24);
            b[0] = product(m, x);
            y = Pack(b);

            return y;
        }

        private static byte ByteSub(byte x)
        {
            byte y;

            y = ptab[255 - ltab[x]];
            x = y;
            x = RotateLeft(x, 1);
            y ^= x;
            x = RotateLeft(x, 1);
            y ^= x;
            x = RotateLeft(x, 1);
            y ^= x;
            x = RotateLeft(x, 1);
            y ^= x;
            y ^= 0x63;

            return y;
        }

        private static void gentables()
        {
            byte y;
            byte[] b = new byte[4];

            ltab[0] = 0;
            ptab[0] = 1;
            ltab[1] = 0;
            ptab[1] = 3;
            ltab[3] = 1;

            for (int i = 2; i <= 255; i++)
            {
                ptab[i] = (byte)(ptab[i - 1] ^ xtime(ptab[i - 1]));
                ltab[ptab[i]] = (byte)i;
            }

            fbsub[0] = 0x63;
            rbsub[0x63] = 0;

            for (int i = 1; i <= 255; i++)
            {
                y = ByteSub((byte)i);
                fbsub[i] = y;
                rbsub[y] = (byte)i;
            }

            y = 1;
            for (int i = 0; i <= 29; i++)
            {
                rco[i] = y;
                y = xtime(y);
            }

            for (int i = 0; i <= 255; i++)
            {
                y = fbsub[i];
                b[3] = (byte)(y ^ xtime(y));
                b[2] = y;
                b[1] = y;
                b[0] = xtime(y);
                ftable[i] = Pack(b);

                y = rbsub[i];
                b[3] = bmul(InCo[0], y);
                b[2] = bmul(InCo[1], y);
                b[1] = bmul(InCo[2], y);
                b[0] = bmul(InCo[3], y);
                rtable[i] = Pack(b);
            }
        }

        private static void gkey(int nb, int nk, byte[] key)
        {
            int i, j, k, m, N;
            int C1, C2, C3;
            uint[] CipherKey = new uint[8];

            Nb = nb;
            Nk = nk;

            if (Nb >= Nk)
                Nr = 6 + Nb;
            else
                Nr = 6 + Nk;

            C1 = 1;
            if (Nb < 8)
            {
                C2 = 2;
                C3 = 3;
            }
            else
            {
                C2 = 3;
                C3 = 4;
            }

            for (m = j = 0; j < nb; j++, m += 3)
            {
                fi[m] = (byte)((j + C1) % nb);
                fi[m + 1] = (byte)((j + C2) % nb);
                fi[m + 2] = (byte)((j + C3) % nb);

                ri[m] = (byte)((nb + j - C1) % nb);
                ri[m + 1] = (byte)((nb + j - C2) % nb);
                ri[m + 2] = (byte)((nb + j - C3) % nb);
            }

            N = Nb * (Nr + 1);

            for (i = j = 0; i < Nk; i++, j += 4)
                CipherKey[i] = PackFrom(key, j);

            for (i = 0; i < Nk; i++)
                fkey[i] = CipherKey[i];

            for (j = Nk, k = 0; j < N; j += Nk, k++)
            {
                fkey[j] = fkey[j - Nk] ^ SubByte(RotateLeft(fkey[j - 1], 24)) ^ rco[k];

                if (Nk <= 6)
                {
                    for (i = 1; i < Nk && (i + j) < N; i++)
                        fkey[i + j] = fkey[i + j - Nk] ^ fkey[i + j - 1];
                }
                else
                {
                    for (i = 1; i < 4 && (i + j) < N; i++)
                        fkey[i + j] = fkey[i + j - Nk] ^ fkey[i + j - 1];

                    if ((j + 4) < N)
                        fkey[j + 4] = fkey[j + 4 - Nk] ^ SubByte(fkey[j + 3]);

                    for (i = 5; i < Nk && (i + j) < N; i++)
                        fkey[i + j] = fkey[i + j - Nk] ^ fkey[i + j - 1];
                }
            }

            for (j = 0; j < Nb; j++)
                rkey[j + N - Nb] = fkey[j];

            for (i = Nb; i < (N - Nb); i += Nb)
            {
                k = N - Nb - i;

                for (j = 0; j < Nb; j++)
                    rkey[k + j] = InvMixCol(fkey[i + j]);

            }

            for (j = (N - Nb); j < N; j++)
                rkey[j - N + Nb] = fkey[j];
        }

        private static void decrypt(byte[] buff)
        {
            int i, j, k, m;
            uint[] a = new uint[8];
            uint[] b = new uint[8];
            uint[] x, y, t;

            for (i = j = 0; i < Nb; i++, j += 4)
            {
                a[i] = PackFrom(buff, j);
                a[i] ^= rkey[i];
            }

            k = Nb;
            x = a;
            y = b;

            for (i = 1; i < Nr; i++)
            {
                for (m = j = 0; j < Nb; j++, m += 3)
                    y[j] = rkey[k++] ^ rtable[(byte)x[j]] ^
                        RotateLeft(rtable[(byte)(x[ri[m]] >> 8)], 8) ^
                        RotateLeft(rtable[(byte)(x[ri[m + 1]] >> 16)], 16) ^
                        RotateLeft(rtable[x[ri[m + 2]] >> 24], 24);

                t = x;
                x = y;
                y = t;
            }

            for (m = j = 0; j < Nb; j++, m += 3)
                y[j] = rkey[k++] ^ (uint)rbsub[(byte)x[j]] ^
                    RotateLeft((uint)rbsub[(byte)(x[ri[m]] >> 8)], 8) ^
                    RotateLeft((uint)rbsub[(byte)(x[ri[m + 1]] >> 16)], 16) ^
                    RotateLeft((uint)rbsub[x[ri[m + 2]] >> 24], 24);

            for (i = j = 0; i < Nb; i++, j += 4)
            {
                UnpackFrom(y[i], buff, j);
                x[i] = y[i] = 0;
            }
        }

        // -------------------------------------------------------------------------------------
        // The code below are utility functions for calling the Rijndael code above
        // -------------------------------------------------------------------------------------
        /// <summary>This version of DecryptData takes the encrypted message, password 
        /// and IV as byte arrays and decrypts the message, returning the plain text as 
        /// a byte array.
        /// </summary>
        /// <param name="message">The encrypted message</param>
        /// <param name="password">The password/key that was used to encrypt the message</param>
        /// <param name="initialisationVector">The IV</param>
        /// <param name="blockSize">The block size used in encrypting the message</param>
        /// <param name="keySize">The key size used in encrypting the message</param>
        /// <param name="cryptMode">The encryption mode, CBC or ECB, used in encrypting the message</param>
        public static byte[] DecryptData(byte[] message, byte[] password,
            byte[] initialisationVector, BlockSize blockSize,
            KeySize keySize, EncryptionMode cryptMode)
        {
            byte[] messageData, keyBlock, vectorBlock, dataBlock;
            int messageLength, encodedLength;

            // Dont do any work if message is empty
            encodedLength = message.Length;
            if (encodedLength <= 0)
                return message;
            var nb = blockSize switch
            {
                BlockSize.Block128 => 4,
                BlockSize.Block192 => 6,
                // assume 256
                _ => 8,
            };
            vectorBlock = new byte[nb * 4];
            dataBlock = new byte[nb * 4];

            for (int i = 0; i < (nb * 4); i++)
            {
                vectorBlock[i] = 0;
                dataBlock[i] = 0;
            }

            var nk = keySize switch
            {
                KeySize.Key128 => 4,
                KeySize.Key192 => 6,
                // assume 256
                _ => 8,
            };
            keyBlock = new byte[nk * 4];

            for (int i = 0; i < (nk * 4); i++)
            {
                keyBlock[i] = 0;
            }

            // Key will be zero padded, or trimmed to correct size
            for (int i = 0; (i < password.Length) && (i < (nk * 4)); i++)
                keyBlock[i] = password[i];

            // Vector will be zero padded, or trimmed to correct size
            for (int i = 0; (i < initialisationVector.Length) && (i < (nb * 4)); i++)
                vectorBlock[i] = initialisationVector[i];

            // Prepare the key and tables using the Rijndael fuinctions
            gentables();
            gkey(nb, nk, keyBlock);

            // Decrypt a block at a time
            for (int i = 0; i < encodedLength; i += (nb * 4))
            {
                Array.Copy(message, i, dataBlock, 0, (nb * 4));

                decrypt(dataBlock);

                // If CBC mode we need to do some extra XORing
                if (cryptMode == EncryptionMode.ModeCBC)
                {
                    for (int j = 0; j < (nb * 4); j++)
                        dataBlock[j] ^= vectorBlock[j];

                    Array.Copy(message, i, vectorBlock, 0, (nb * 4));
                }

                Array.Copy(dataBlock, 0, message, i, (nb * 4));
            }

            // Remove padding
            var last = message[encodedLength - 1];
            if (encodedLength <= last)
            {
                messageLength = encodedLength;
            }
            else
            {
                messageLength = encodedLength - last;
            }

            // Get the original message from the clear text
            messageData = new byte[messageLength];
            Array.Copy(message, messageData, messageLength);

            return messageData;
        }
    }
}
