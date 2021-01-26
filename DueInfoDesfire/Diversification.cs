using SpringCard.LibCs;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
namespace DueInfo
{
    public class Diversification
    {
        static byte[] init_vector = new byte[16];

        static byte[] cmac_subkey_0 = new byte[16];
        static byte[] cmac_subkey_1 = new byte[16];
        static byte[] cmac_subkey_2 = new byte[16];

        static private byte[] AESEncrypt(byte[] key, byte[] iv, byte[] data)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                AesCryptoServiceProvider aes = new AesCryptoServiceProvider();

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();

                    return ms.ToArray();
                }
            }
        }
        static private byte[] Rol(byte[] b)
        {
            byte[] r = new byte[b.Length];
            byte carry = 0;

            for (int i = b.Length - 1; i >= 0; i--)
            {
                ushort u = (ushort)(b[i] << 1);
                r[i] = (byte)((u & 0xff) + carry);
                carry = (byte)((u & 0xff00) >> 8);
            }

            return r;
        }
        static private byte[] AESCMAC(byte[] key, byte[] data)
        {
            // SubKey generation
            // step 1, AES-128 with key K is applied to an all-zero input block.
            byte[] L = AESEncrypt(key, new byte[16], new byte[16]);

            // step 2, K1 is derived through the following operation:
            byte[] FirstSubkey = Rol(L); //If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
            if ((L[0] & 0x80) == 0x80)
                FirstSubkey[15] ^= 0x87; // Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.

            // step 3, K2 is derived through the following operation:
            byte[] SecondSubkey = Rol(FirstSubkey); // If the most significant bit of K1 is equal to 0, K2 is the left-shift of K1 by 1 bit.
            if ((FirstSubkey[0] & 0x80) == 0x80)
                SecondSubkey[15] ^= 0x87; // Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of K1 by 1 bit.

            // MAC computing
            if (((data.Length != 0) && (data.Length % 16 == 0)) == true)
            {
                // If the size of the input message block is equal to a positive multiple of the block size (namely, 128 bits),
                // the last block shall be exclusive-OR'ed with K1 before processing
                for (int j = 0; j < FirstSubkey.Length; j++)
                    data[data.Length - 16 + j] ^= FirstSubkey[j];
            }
            else
            {
                // Otherwise, the last block shall be padded with 10^i
                byte[] padding = new byte[16 - data.Length % 16];
                padding[0] = 0x80;

                data = data.Concat<byte>(padding.AsEnumerable()).ToArray();

                // and exclusive-OR'ed with K2
                for (int j = 0; j < SecondSubkey.Length; j++)
                    data[data.Length - 16 + j] ^= SecondSubkey[j];
            }

            // The result of the previous process will be the input of the last encryption.
            byte[] encResult = AESEncrypt(key, init_vector/*new byte[16]*/, data);

            byte[] HashValue = new byte[16];
            Array.Copy(encResult, encResult.Length - HashValue.Length, HashValue, 0, HashValue.Length);

            return HashValue;
        }

        static private void init(byte[] base_key)
        {
            byte bMSB;
            byte block_size = 0;
            byte rb_xor_value = 0;
            /*BYTE abSavedInitVktr[16];
            DWORD t, i;*/
            int i = 0;

            /*KEY_ISO_AES*/
            rb_xor_value = 0x87;
            block_size = 16;

            cmac_subkey_0 = AESEncrypt(base_key, init_vector, cmac_subkey_0);
            Array.Copy(cmac_subkey_0, 0, cmac_subkey_1, 0, cmac_subkey_0.Length);
            // If the MSBit of the generated cipher == 1 -> K1 = (cipher << 1) ^ Rb ...
            // store MSB:
            bMSB = cmac_subkey_1[0];

            // Shift the complete cipher for 1 bit ==> K1:
            for (i = 0; i < (int)(block_size - 1); i++)
            {
                cmac_subkey_1[i] <<= 1;
                // add the carry over bit:
                cmac_subkey_1[i] |= (byte)(((cmac_subkey_1[i + 1] & 0x80) == 0x80 ? 0x01 : 0x00));
            }
            cmac_subkey_1[block_size - 1] <<= 1;
            if ((bMSB & 0x80) == 0x80)
            {
                // XOR with Rb:
               cmac_subkey_1[block_size - 1] ^= rb_xor_value;
            }

            // store MSB:
            bMSB = cmac_subkey_1[0];

            // Shift K1 ==> K2:
            for (i = 0; i < (int)(block_size - 1); i++)
            {
                cmac_subkey_2[i] = (byte)(cmac_subkey_1[i] << 1);
                cmac_subkey_2[i] |= (byte)(((cmac_subkey_1[i + 1] & 0x80) == 0x80 ? 0x01 : 0x00));
            }
            cmac_subkey_2[block_size - 1] = (byte) (cmac_subkey_1[block_size - 1] << 1);

            if ((bMSB & 0x80) == 0x80)
            {
                // XOR with Rb:
                cmac_subkey_2[block_size - 1] ^= rb_xor_value;
            }

        }

        static public int Diversification_AES128(byte[] base_key, byte[] diversification_input, int diversification_lenght, ref byte[] diversified_key)
        {
            int i = 0;
            byte[] M = new byte[32];
            bool padd = false;

            for (i = 0; i < 16; i++)
            {
                cmac_subkey_0[i] = cmac_subkey_1[i] = cmac_subkey_2[i] = 0x00;
            }

            // prepare the padding 
            init(base_key);
#if _DEBUG_DIVERSIFICATION
            LogManager.DoLogOperation(string.Format("TEST K0={0}", BinConvert.ToHex(cmac_subkey_0)));
            LogManager.DoLogOperation(string.Format("TEST K1={0}", BinConvert.ToHex(cmac_subkey_1)));
            LogManager.DoLogOperation(string.Format("TEST K2={0}", BinConvert.ToHex(cmac_subkey_2)));
#endif

            // add the div constant at the beginning of M
            M[0] = 0x01;
            for (i = 0; i < diversification_lenght; i++)
            {
                M[1 + i] = diversification_input[i];
            }
            i++;

            // add the padding
            if (((i % 32)!=0) && (i < 32))
            {
                M[i] = 0x80;
                i++;
                for (; i < 32; i++)
                {
                    M[i] = 0x00;
                }
                padd = true;
            }
#if _DEBUG_DIVERSIFICATION
            LogManager.DoLogOperation(string.Format("CMAC Input D={0}", BinConvert.ToHex(M, 32)));
#endif

            /* XOR the last 16 bytes with CMAC_SubKey */
            for (i = 0; i < 16; i++)
            {
                if (padd)
                    M[16 + i] ^= cmac_subkey_2[i];
                else
                    M[16 + i] ^= cmac_subkey_1[i];
            }


#if _DEBUG_DIVERSIFICATION
            LogManager.DoLogOperation(string.Format("XOR the last 16 bytes with CMAC_SubKey2={0}", BinConvert.ToHex(M, 32)));
            int lsize = 32;
#endif

            byte[] IV= new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            

            /* Encryption using M */
            byte[] result = AES_Encrypt(M, base_key, IV);

#if _DEBUG_DIVERSIFICATION
            LogManager.DoLogOperation(string.Format("Encryption using M={0}", BinConvert.ToHex(M, lsize)));
#endif

            for (i = 0; i < 16; i++)
                diversified_key[i] = result[16 + i];

#if _DEBUG_DIVERSIFICATION
            LogManager.DoLogOperation(string.Format("Diversification key={0}", BinConvert.ToHex(diversified_key, 16)));
#endif

            return 0;
        }
        public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] key, byte[] IV)
        {
            byte[] encryptedBytes = null;
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged aes = new RijndaelManaged())
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Key = key;
                    aes.IV = IV;
                    aes.Mode = CipherMode.CBC;
                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }
            return encryptedBytes;
        }        
    }
}