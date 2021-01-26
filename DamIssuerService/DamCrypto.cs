using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DamWebService
{
    class DamCrypto
    {
        public static byte[] AES_Encrypt(byte[] PlainText, byte[] key, byte[] iv)
        {
            AesCryptoServiceProvider aesCSP = new AesCryptoServiceProvider();
            aesCSP.BlockSize = 128;
            aesCSP.Key = key;
            aesCSP.IV = iv;
            aesCSP.Padding = PaddingMode.Zeros;
            aesCSP.Mode = CipherMode.CBC;

            ICryptoTransform xfrm = aesCSP.CreateEncryptor(key, iv);
            byte[] result = xfrm.TransformFinalBlock(PlainText, 0, PlainText.Length);

            return result;
        }

        /// <summary>
        /// EncK = EDAM(KPICCDAMENC,Random(7)||KAppDAMDefault||KeyVerAppDAMDefault)
        /// </summary>
        /// <param name="PICCDAMENCKey"></param>
        /// <param name="DAMTransport"></param>
        /// <returns></returns>
        public static byte[] EncK(byte[] PICCDAMENCKey, byte[] AppDAMDefault, byte KeyVerAppDAMDefault)
        {
            byte[] IV = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            Random rand = new Random();
            byte[] random = new byte[7];
            for (int i = 0; i < random.Length; i++)
                random[i] = (byte)rand.Next(0x00, 0xFF);

            byte[] input = new byte[AppDAMDefault.Length + 8];
            Array.Copy(random, 0, input, 0, 7);
            Array.Copy(AppDAMDefault, 0, input, 7, 16);
            input[input.Length - 1] = KeyVerAppDAMDefault;

            byte[] EncK = AES_Encrypt(input, PICCDAMENCKey, IV);
            
            return EncK;
        }

        public static byte[] CalculateCMAC(byte[] Key, byte[] IV, byte[] input)
        {
            // First : calculate subkey1 and subkey2
            byte[] Zeros = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            byte[] L = AES_Encrypt(Zeros, Key, IV);

            byte[] Key1;
            byte[] Key2;
            int i = 0;
            byte Rb = 0x87;
            byte MSB_L = L[0];
            UInt32 decal;

            // calcul de Key 1
            for (i = 0; i < L.Length - 1; i++)
            {
                decal = (UInt32)(L[i] << 1);
                L[i] = (byte)(decal & 0x00FF);
                if ((L[i + 1] & 0x80) == 0x80)
                {
                    L[i] |= 0x01;
                }
                else
                {
                    L[i] |= 0x00;
                }
            }

            decal = (UInt32)(L[i] << 1);
            L[i] = (byte)(decal & 0x00FF);

            if (MSB_L >= 0x80)
                L[L.Length - 1] ^= Rb;

            Key1 = L;

            byte[] tmp = new byte[Key1.Length];
            for (int k = 0; k < Key1.Length; k++)
                tmp[k] = Key1[k];

            // Calcul de key 2
            byte MSB_K1 = Key1[0];
            for (i = 0; i < L.Length - 1; i++)
            {
                decal = (UInt32)(tmp[i] << 1);
                tmp[i] = (byte)(decal & 0x00FF);
                if ((tmp[i + 1] & 0x80) == 0x80)
                {
                    tmp[i] |= 0x01;
                }
                else
                {
                    tmp[i] |= 0x00;
                }
            }
            decal = (UInt32)(tmp[i] << 1);
            tmp[i] = (byte)(decal & 0x00FF);
            if (MSB_K1 >= 0x80)
                tmp[tmp.Length - 1] ^= Rb;

            Key2 = tmp;

            byte[] result;

            /*-------------------------------------------------*/
            /* Cas 1 : la chaine est vide    */
            /* a- On concatene avec 0x80000000..00  (data) */
            /* b- on X-or avec Key2  (M1)*/
            /* c- on encrypte en AES-128 avec K et IV */
            /**/
            if (input == null)
            {
                byte[] data = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                byte[] M1 = new byte[16];
                for (int k = 0; k < 16; k++)
                    M1[k] = (byte)(data[k] ^ Key2[k]); // input      

                result = AES_Encrypt(M1, Key, IV);
            }
            else

            /**/

            /*--------------------------------------------------*/
            /* Cas 2 ! la chaine n'est pas vide et contient 16 octets  */
            /* a- on X-or avec Key 1 (data)  */
            /* b- on encrypte en AES-128 avec K et IV  */
            // byte[] data = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };      


            if (input.Length == 16)
            {
                byte[] M1 = new byte[input.Length];
                for (int k = 0; k < input.Length; k++)
                    M1[k] = (byte)(input[k] ^ Key1[k]);

                result = AES_Encrypt(M1, Key, IV);
            }
            else
            {
                byte[] M = new byte[input.Length + 16];
                int offset = 0;
                for (i = 0; i < input.Length; i += 16)
                {
                    if ((i + 16) < input.Length)
                    {
                        /* block entier - on ne padde pas */
                        for (int j = 0; j < 16; j++)
                            M[offset++] = (byte)(input[i + j]);// ^ Key1[j]);

                    }
                    else
                    if ((i + 16) == input.Length)
                    {
                        /* block entier, on doit padder avec Key 1 */
                        for (int j = 0; j < 16; j++)
                            M[offset++] = (byte)(input[i + j] ^ Key1[j]);

                    }
                    else
                    {
                        /* block terminal */
                        byte remaining = (byte)(input.Length - i);
                        byte NbPadd = (byte)(16 - remaining);


                        for (int j = 0; j < remaining; j++)
                            M[offset++] = (byte)(input[i + j] ^ Key2[j]);

                        byte key2_index_when_input_ends = (byte)(input.Length % 16);
                        M[offset++] = (byte)(0x80 ^ Key2[key2_index_when_input_ends]);
                        NbPadd--;
                        key2_index_when_input_ends++;
                        for (int j = 1; j <= NbPadd; j++)
                            M[offset++] = Key2[remaining + j];

                    }

                }

                byte[] Message = new byte[offset];
                Array.ConstrainedCopy(M, 0, Message, 0, offset);

                result = AES_Encrypt(Message, Key, IV);
            }
            return result;

        }

        /// <summary>
        /// DAMMAC = MACtDAM(KPICCDAMMAC,Cmd||AID||DAMSlotNo
        /// ||DAMSlotVersion||QuotaLimit||KeySett1||KeySett2
        /// [|| AKSVersion || NoKeySets || MaxKeySize || RollKey]
        /// [|| ISOFileID][|| ISODFName]||EncK)
        /// </summary>
        /// <param name="PICCDAMMACKey"></param>
        /// <param name="cmd"></param>
        /// <param name="aid"></param>
        /// <param name="damSlotNo"></param>
        /// <param name="damSlotVersion"></param>
        /// <param name="quotaLimit"></param>
        /// <param name="key_setting_1"></param>
        /// <param name="key_setting_2"></param>
        /// <param name="key_setting_3"></param>
        /// <param name="aks_version"></param>
        /// <param name="NoKeySets"></param>
        /// <param name="MaxKeySize"></param>
        /// <param name="AppKeySetSett"></param>
        /// <param name="ENCK"></param>
        /// <returns></returns>
        public static byte[] DAMMAC(
            byte[] PICCDAMMACKey,
            byte cmd,
            UInt32 aid,
            UInt16 damSlotNo,
            byte damSlotVersion,
            UInt16 quotaLimit,
            byte key_setting_1,
            byte key_setting_2,
            byte key_setting_3,
            byte aks_version,
            byte NoKeySets,
            byte MaxKeySize,
            byte Aks,
            ushort iso_df_id,
            byte[] iso_df_name,
            byte[] ENCK)
        {

            byte[] IV = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] input;
            int input_lenght = 0;

            if ((key_setting_2 & 0x10) == 0x10)
            {
                input_lenght++;
                if ((key_setting_3 & 0x01) == 0x01)
                {
                    input_lenght++;
                    if ((NoKeySets >= 2) && (NoKeySets <= 16))
                    {
                        input_lenght++;
                        if ((NoKeySets == 0x10) || (NoKeySets == 18))
                        {
                            input_lenght++;
                        }
                        input_lenght++;
                    }
                }
            }

            if (iso_df_name != null)
                input = new byte[11 + ENCK.Length + (iso_df_name.Length + 2) + input_lenght];
            else
                input = new byte[11 + ENCK.Length + input_lenght];

            input_lenght = 0;
            input[input_lenght++] = cmd;
            input[input_lenght++] = (byte)(aid & 0x000000FF);
            input[input_lenght++] = (byte)((aid >> 8) & 0x00FF);
            input[input_lenght++] = (byte)((aid >> 16) & 0x00FF);
            input[input_lenght++] = (byte)(damSlotNo & 0x00FF);
            input[input_lenght++] = (byte)(damSlotNo >> 8);
            input[input_lenght++] = damSlotVersion;
            input[input_lenght++] = (byte)(quotaLimit & 0x00FF);
            input[input_lenght++] = (byte)(quotaLimit >> 8);
            input[input_lenght++] = key_setting_1;
            input[input_lenght++] = key_setting_2;

            if ((key_setting_2 & 0x10) == 0x10)
            {
                input[input_lenght++] = key_setting_3;
                if ((key_setting_3 & 0x01) == 0x01)
                {
                    input[input_lenght++] = aks_version;
                    if ((NoKeySets >= 2) && (NoKeySets <= 16))
                    {
                        input[input_lenght++] = NoKeySets;
                        if ((NoKeySets == 0x10) || (NoKeySets == 18))
                        {
                            input[input_lenght++] = MaxKeySize;
                        }

                        input[input_lenght++] = Aks;
                    }
                }
            }

            if (iso_df_name != null)
            {
                input[input_lenght++] = (byte)(iso_df_id & 0x00FF);
                input[input_lenght++] = (byte)(iso_df_id >> 8);

                for (int i = 0; i < iso_df_name.Length; i++)
                    input[input_lenght++] = iso_df_name[i];
            }
            /* add encK at the end */
            for (int i = 0; i < ENCK.Length; i++)
                input[input_lenght++] = ENCK[i];

            byte[] CMAC_enormous = CalculateCMAC(PICCDAMMACKey, IV, input);

            
            byte[] CMAC_full = new byte[16];
            Array.ConstrainedCopy(CMAC_enormous, CMAC_enormous.Length - 16, CMAC_full, 0, 16);

            
            byte[] CMAC = new byte[8];
            int j = 0;

            for (int i = 1; i < CMAC_full.Length;)
            {
                CMAC[j++] = CMAC_full[i];
                i += 2;
            }
            return CMAC;
        }
    }
}
