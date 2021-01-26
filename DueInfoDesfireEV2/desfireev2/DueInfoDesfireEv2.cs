using DueInfoDesfireEV2;
using SpringCard.LibCs;
using SpringCard.PCSC;
using SpringCard.PCSC.CardHelpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DueInfo.desfireev2
{
    public class DueInfoDesfireEv2 : Desfire
    {

        public byte[] AesKeyMaster { get; set; }
        //public byte[] AesNewKeyMaster { get; set; }
        public byte[] AesKeyDueInfo { get; set; }
        public byte[] Escn { get; set; }

        public byte[] DAMAuthKey { get; set; }
        public byte[] DAMMACKey { get; set; }
        public byte[] DAMENCKey { get; set; }

        public byte[] EncK { get; set; }
        public byte[] DAMMAC { get; set; }

        protected byte[] AesKeyDiversified = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        private byte[] TransportKey = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        /* DUEINFO provided by NXP */
        private uint m_Aid = 0xF58840;
        private bool _error_openssl = false;
        private AutoResetEvent wait_process_end = new AutoResetEvent(false);
        private string openssl_message;

        string sign_file = "pem\\sign.sha256";
        string escn_data = "pem\\escn.data";

        string pub_key_file = "pem\\ca.intermediate.public.pem";
        string priv_key_file = "pem\\ca.intermediate.key.pem";

        string cert_der_file = "pem\\ca.intermediate.cert.der";
        string cert_pem_file = "pem\\ca.intermediate.cert.pem";

        public DueInfoDesfireEv2(ICardTransmitter transmitter, byte isoWrapping = 0) : base(transmitter, isoWrapping)
        {

        }

        public bool Format()
        {
            long rc = 0;
            byte KeyId = 0x00;


            LogManager.DoLogOperation("[DEBUG] Select Application");
            rc = this.SelectApplication(0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'SelectApplication' {0} command failed - rc= {1:X}\t", 0x000000, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            byte version = 0x00;
            rc = this.GetKeyVersion(0x00, ref version);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'GetApplicationIDs' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            /*byte aid_max_count = 30;
            uint[] aid_list = new uint[aid_max_count];
            byte aid_count = 15;

            rc = this.GetApplicationIDs(aid_max_count, ref aid_list, ref aid_count);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'GetApplicationIDs' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation(string.Format("[DEBUG] aid_count =" + aid_count));
            for (int i = 0; i < aid_count; i++)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] AID{0} = {1:X}", i, aid_list[i]));
            }*/
            LogManager.DoLogOperation("[DEBUG] Authentificate");
            rc = this.AuthenticateAes(KeyId, AesKeyMaster);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'Authenticate' {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation("[DEBUG] FormatPICC");
            rc = this.FormatPICC();
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'FormatPICC' {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            uint pdwFreeBytes = 0;
            this.GetFreeMemory(ref pdwFreeBytes);
            LogManager.DoLogOperation(string.Format("[DEBUG] Desfire FreeMem' {0}", pdwFreeBytes));

            ResetPICCDAMKeys();
            return true;
        }
        /// <summary>
        /// Look for DUEINFO and delete it if exists
        /// </summary>
        /// <returns></returns>
        public bool Disable()
        {
            long rc = 0;
            byte KeyId = 0x00;


            LogManager.DoLogOperation("[DEBUG] Select Application");
            rc = this.SelectApplication(0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'SelectApplication' {0} command failed - rc= {1:X}\t", 0x000000, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            byte aid_max_count = 30;
            uint[] aid_list = new uint[aid_max_count];
            byte aid_count = 15;

            rc = this.GetApplicationIDs(aid_max_count, ref aid_list, ref aid_count);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'GetApplicationIDs' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation(string.Format("[DEBUG] aid_count =" + aid_count));
            for (int i = 0; i < aid_count; i++)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] AID{0} = {1:X}", i, aid_list[i]));
                if (aid_list[i] == m_Aid)
                {
                    LogManager.DoLogOperation("[DEBUG] Authentificate");
                    rc = this.AuthenticateAes(KeyId, AesKeyMaster);
                    if (rc != SCARD.S_SUCCESS)
                    {
                        LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'Authenticate' {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                        return false;
                    }

                    byte[] uid = new byte[8];
                    LogManager.DoLogOperation("[DEBUG] Get UID");
                    rc = this.GetCardUID(out uid);
                    if (rc != SCARD.S_SUCCESS)
                    {
                        LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'GetCardUID' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                        return false;
                    }
                    LogManager.DoLogOperation("UID " + BinConvert.ToHex(uid));

                    rc = this.DeleteApplication(m_Aid);
                    if (rc != SCARD.S_SUCCESS)
                    {
                        LogManager.DoLogOperation(string.Format("[ERROR]DeleteApplication fails {0}", rc));
                        return false;
                    }
                    else
                    {
                        LogManager.DoLogOperation("[DEBUG] DeleteApplication");
                        uint pdwFreeBytes = 0;
                        this.GetFreeMemory(ref pdwFreeBytes);
                        LogManager.DoLogOperation(string.Format("[DEBUG] Desfire FreeMem' {0}", pdwFreeBytes));
                        return true;
                    }
                }
            }
            LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'Erase DUEINFO' AID not found"));
            return false;
        }




        /// <summary>
        /// Write DUEINFO application
        /// </summary>
        /// <returns></returns>
        public bool Create()
        {
            int i = 0;
            /*a0e4cacc - c5a8 - 441f - af57 - e7bd46d3b4ce*/
            byte[] sign = null;
            byte[] cert = null;
            //string filename = "esdn.sha256";
            string filename;
            long rc = 0;
            byte[] uid = new byte[8];
            byte KeyId = 0x00;
            byte file_id = 0x00;
            /* communication plain text for clear access */
            byte comm_mode = 0x00;
            /* read access clear 'E' */
            /* write access '0' master key only */
            /* read/write access clear '0' */
            /* change acces rights '0' master key only */
            UInt16 access_rights = 0xE000;

            byte aid_max_count = 30;
            uint[] aid_list = new uint[aid_max_count];
            byte aid_count = 15;
            List<string> sign_args = new List<string>();

            sign_args.Add("version");
            if (call_openssl(sign_args, Console_OpenSsl.ActionOpenSsl.actVersion) == false)
            {
                return false;
            }
            sign_args.Clear();


            filename = cert_der_file;
            if (File.Exists(filename))
            {
                using (FileStream sourceFile = new FileStream(filename, FileMode.Open))
                {
                    using (BinaryReader reader = new BinaryReader(sourceFile))
                    {
                        cert = new byte[sourceFile.Length];
                        cert = reader.ReadBytes(cert.Length);
                        reader.Close();
                    }
                    sourceFile.Close();
                }
            }
            if (cert == null)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire Fails to read certificate {0}", filename));
                return false;
            }

            /* select Desfire master application */
            LogManager.DoLogOperation("[DEBUG] Select Application");
            rc = this.SelectApplication(0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'SelectApplication' {0} command failed - rc= {1:X}\t", 0x000000, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            

            /* List Desfire AID */
            rc = this.GetApplicationIDs(aid_max_count, ref aid_list, ref aid_count);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'GetApplicationIDs' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation(string.Format("[DEBUG] aid_count =" + aid_count));
            for (i = 0; i < aid_count; i++)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] AID{0} = {1:X}", i, aid_list[i]));
                if (aid_list[i] == m_Aid)
                {
                    LogManager.DoLogOperation("[DEBUG] DUEINFO already exists !!!");
                    return false;
                }
            }

            /* Authentificate */
            LogManager.DoLogOperation("[DEBUG] Authentificate TDES with master key");
            rc = this.AuthenticateAes(KeyId, AesKeyMaster);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'Authenticate' {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* retrieve DESFIRE UID */
            LogManager.DoLogOperation("[DEBUG] Get UID");
            rc = this.GetCardUID(out uid);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'GetCardUID' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation("[DEBUG] UID " + BinConvert.ToHex(uid));

            using (BinaryWriter writer = new BinaryWriter(File.Open(escn_data, FileMode.Create)))
            {
                writer.Write(Escn);
                writer.Write(uid);
                writer.Close();
            }
            /* create signature from ESCN|UID */
            LogManager.DoLogOperation("[DEBUG] Openssl create escn signature with university private key");


            sign_args.Add("test");
            sign_args.Add(priv_key_file);
            sign_args.Add(sign_file);
            sign_args.Add(escn_data);
            if (call_openssl(sign_args, Console_OpenSsl.ActionOpenSsl.actSign) == false)
            {
                return false;
            }
            sign_args.Clear();

            if (File.Exists(sign_file))
            {
                using (FileStream sourceFile = new FileStream(sign_file, FileMode.Open))
                {
                    if (sourceFile.Length == 0)
                    {
                        sourceFile.Close();
                        LogManager.DoLogOperation(string.Format("[DEBUG] Signature file is empty {0}", sign_file));
                        return false;
                    }
                    using (BinaryReader reader = new BinaryReader(sourceFile))
                    {
                        sign = new byte[sourceFile.Length];
                        sign = reader.ReadBytes(sign.Length);
                        reader.Close();
                    }
                    sourceFile.Close();
                }
            }
            if (sign == null)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire Fails to read signature {0}", filename));
                return false;
            }

            /* set configuration */
            byte[] setting = new byte[2];


            /* enable random ID */
            //setting[0] = 0x02;
            rc = this.SetConfiguration(0x00, setting, 1);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[ERROR]SetConfiguration fails {0}", rc));
                return false;
            }
            /* read rest of memory */
            LogManager.DoLogOperation("[DEBUG] GetFreeMemory");
            uint pdwFreeBytes = 0;
            if (rc != SCARD.S_SUCCESS)
            {
                this.GetFreeMemory(ref pdwFreeBytes);
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire FreeMem' {0}", pdwFreeBytes));
                return true;
            }

            /*create application */
            /* 0x0A -> configuration changeable, free directory list access without master key */
            /* 0xA7 -> AES operation, ISO enbaled, 14 keys can be stored */
            //rc = this.CreateApplication(m_Aid, 0x0A, 0x87);
            UInt16 iso_df_id = 0x1000;
            byte[] iso_df_name = new byte[] { 0xA0, 0x00, 0x00, 0x06, 0x14, 0x04, 0xF5, 0x88, 0x40 };
            rc = this.CreateIsoApplication(m_Aid, 0x0A, 0xA7, iso_df_id, iso_df_name, (byte)iso_df_name.Length);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[ERROR]CreateApplication fails {0}", rc));
                return false;
            }

            rc = this.GetApplicationIDs(aid_max_count, ref aid_list, ref aid_count);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'GetApplicationIDs' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation(string.Format("[DEBUG] aid_count =" + aid_count));
            for (i = 0; i < aid_count; i++)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] [DEBUG] AID{0} = {1:X}", i, aid_list[i]));
                if (aid_list[i] == m_Aid)
                {
                    break;
                }
            }
            if (aid_count == i)
            {
                LogManager.DoLogOperation("[DEBUG] DUEINFO not found after creation !!!");
                return false;
            }
            /* select Desfire master application */
            LogManager.DoLogOperation("[DEBUG] Select DUEINFO Application");
            rc = this.SelectApplication(m_Aid);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'SelectApplication' DUEINFO {0} command failed - rc= {1:X}\t", 0x000000, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation("[DEBUG] Authentificate DUEINFO with master key");
            rc = this.AuthenticateAes(KeyId, AesKeyMaster);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'Authenticate' DUEINFO {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* Create ESCN Standards files */
            LogManager.DoLogOperation("[DEBUG] DUEINFO create Standard file for ESCN");
            rc = this.CreateIsoStdDataFile(file_id, 0x1001, comm_mode, access_rights, (uint)Escn.Length);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'CreateStdDataFile' ECSN {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation("[DEBUG] DUEINFO write ESCN");
            rc = this.WriteData(file_id, comm_mode, 0, (uint)Escn.Length, Escn);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'WriteData' ECSN {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* Create SIGNATURE Standard file */
            file_id = 0x01;
            LogManager.DoLogOperation("[DEBUG] DUEINFO create Standard file for SIGNATURE");
            rc = this.CreateIsoStdDataFile(file_id, 0x1002, comm_mode, access_rights, (uint)sign.Length);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'CreateStdDataFile' SIGNATURE {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation("[DEBUG] DUEINFO write SIGNATURE");
            rc = this.WriteData(file_id, comm_mode, 0, (uint)sign.Length, sign);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'WriteData' SIGNATURE {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* Create DER Standard file */
            file_id = 0x02;
            LogManager.DoLogOperation("[DEBUG] DUEINFO create Standard file for CERTIFICATE");
            rc = this.CreateIsoStdDataFile(file_id, 0x1003, comm_mode, access_rights, (uint)cert.Length);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'CreateStdDataFile' CERTIFICATE {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation("[DEBUG] DUEINFO write CERTIFICATE");
            rc = this.WriteData(file_id, comm_mode, 0, (uint)cert.Length, cert);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'WriteData' CERTIFICATE {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            #region diversified

            LogManager.DoLogOperation("[DEBUG] DUEINFO set ESCN diversified key");
            /* key 01 is diversified with escn */
            DueInfo.Diversification.Diversification_AES128(AesKeyDueInfo, Escn, Escn.Length, ref AesKeyDiversified);
            /* we set à diversified key even if random UID is not enabled */
            rc = this.ChangeKeyAes(0x01, 0x01, AesKeyDiversified, TransportKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKeyAes' {0} command failed - rc= {1:X}", 0x01, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation("[DEBUG] DUEINFO set UID diversified key");
            /* key 02 is diversified with uid */
            DueInfo.Diversification.Diversification_AES128(AesKeyDueInfo, uid, uid.Length, ref AesKeyDiversified);
            /* we set à diversified key even if random UID is not enabled */
            rc = this.ChangeKeyAes(0x02, 0x01, AesKeyDiversified, TransportKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKeyAes' {0} command failed - rc= {1:X}", 0x01, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            #endregion
            LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'DUEINFO' AID creation Ok ..."));
            return false;

        }

        /// <summary>
        /// Look for DUEINFO and delete it if exists
        /// </summary>
        /// <returns></returns>
        public bool Read(ref byte[] escn, ref byte[] sign, ref byte[] cert)
        {
            long rc = 0;
            byte file_id = 0x00;
            /* communication plain text for clear access */
            byte comm_mode = 0x00;
            uint done = 0;
            byte[] local = new byte[1024];

            /* select Desfire master application */
            LogManager.DoLogOperation("[DEBUG] Select DUEINFO Application");
            rc = this.SelectApplication(m_Aid);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'SelectApplication' DUEINFO {0} command failed - rc= {1:X}\t", 0x000000, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* Read Standard files */

            /* ESCN */
            LogManager.DoLogOperation("[DEBUG] DUEINFO read ESCN");
            rc = this.ReadData(file_id, comm_mode, 0, 0, ref local, ref done);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ReadData' ECSN command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation(string.Format("[DEBUG] DUEINFO read ESCN {0} OK ...", done));

            escn = new byte[done];
            Array.Copy(local, 0, escn, 0, done);
            LogManager.DoLogOperation(BinConvert.ToHex(escn));

            /* SIGNATURE */
            done = 0;
            file_id = 0x01;

            LogManager.DoLogOperation("[DEBUG] DUEINFO read SIGNATURE");
            rc = this.ReadData(file_id, comm_mode, 0, 0, ref local, ref done);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ReadData' ECSN command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation(string.Format("[DEBUG] DUEINFO read SIGNATURE {0} OK ...", done));
            sign = new byte[done];
            Array.Copy(local, 0, sign, 0, done);
            LogManager.DoLogOperation(BinConvert.ToHex(sign));

            /* CERTIFICATE */
            done = 0;
            file_id = 0x02;
            LogManager.DoLogOperation("[DEBUG] DUEINFO read CERTIFICATE");
            rc = this.ReadData(file_id, comm_mode, 0, 0, ref local, ref done);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ReadData' ECSN command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation(string.Format("[DEBUG] DUEINFO read CERTIFICATE {0} OK ...", done));
            cert = new byte[done];
            Array.Copy(local, 0, cert, 0, done);
            LogManager.DoLogOperation(BinConvert.ToHex(cert));

            LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'DUEINFO' read Ok ..."));
            return true;
        }
        public bool Check(byte[] escn, byte[] sign, byte[] cert)
        {
            long rc = 0;
            /* select Desfire master application */
            LogManager.DoLogOperation("[DEBUG] Select DUEINFO Application");
            rc = this.SelectApplication(m_Aid);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'SelectApplication' DUEINFO {0} command failed - rc= {1:X}\t", 0x000000, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            #region diversification
            /* Authentificate for diversification only */
            LogManager.DoLogOperation("[DEBUG] Authentificate with ESCN Diversified key");

            DueInfo.Diversification.Diversification_AES128(AesKeyDueInfo, escn, escn.Length, ref AesKeyDiversified);

            rc = this.AuthenticateAes(0x01, AesKeyDiversified);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'Authenticate' {0} command failed - rc= {1:X}", 0x00, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            #endregion
            /* retrieve DESFIRE UID */
            byte[] uid = new byte[8];

            LogManager.DoLogOperation("[DEBUG] Get UID");
            rc = this.GetCardUID(out uid);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'GetCardUID' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation("[DEBUG] UID " + BinConvert.ToHex(uid));

            JsonRequest.create_auth_json("c:\\dev\\dam_request_auth_key.json", uid);

            /* Authentificate for diversification only */
            LogManager.DoLogOperation("[DEBUG] Authentificate with UID Diversified key");

            DueInfo.Diversification.Diversification_AES128(AesKeyDueInfo, uid, uid.Length, ref AesKeyDiversified);

            rc = this.AuthenticateAes(0x02, AesKeyDiversified);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'Authenticate' {0} command failed - rc= {1:X}", 0x00, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* create temporary files that will be use by openssl */
            using (BinaryWriter writer = new BinaryWriter(File.Open("pem\\ca.dueinfo.cert.der", FileMode.Create)))
            {
                writer.Write(cert);
                writer.Close();
            }
            using (BinaryWriter writer = new BinaryWriter(File.Open(escn_data, FileMode.Create)))
            {
                writer.Write(escn);
                writer.Write(uid);
                writer.Close();
            }
            using (BinaryWriter writer = new BinaryWriter(File.Open(sign_file, FileMode.Create)))
            {
                writer.Write(sign);
                writer.Close();
            }

            /* convert der certificate to pem */
            LogManager.DoLogOperation("[DEBUG] OpenSsl convert certificate from der to pem");
            List<string> sign_args = new List<string>();
            sign_args.Add(cert_der_file);
            sign_args.Add(cert_pem_file);
            if (call_openssl(sign_args, Console_OpenSsl.ActionOpenSsl.actDerToPem) == false)
            {
                return false;
            }
            sign_args.Clear();

            /* extract public key from pem certificate */
            LogManager.DoLogOperation("[DEBUG] Openssl extract public key from certificate");
            sign_args.Add(cert_pem_file);
            sign_args.Add(pub_key_file);
            if (call_openssl(sign_args, Console_OpenSsl.ActionOpenSsl.actExtractPubKey) == false)
            {
                return false;
            }
            sign_args.Clear();
            /* extract public key from pem certificate */
            LogManager.DoLogOperation("[DEBUG] Openssl verify signature with public key from certificate");
            sign_args.Add("test");
            sign_args.Add(pub_key_file);
            sign_args.Add(sign_file);
            sign_args.Add(escn_data);
            if (call_openssl(sign_args, Console_OpenSsl.ActionOpenSsl.actSignVerify) == false)
            {
                return false;
            }
            sign_args.Clear();
            return true;

        }
        #region DEStoAESMasterKey
        /// <summary>
        /// Change master key from DES type to AES.
        /// </summary>
        /// 
        /// <returns></returns>
        public bool ChangeMasterKeyToAES()
        {
            long rc = 0;
            byte KeyId = 0x00;

            /* select Desfire master application */
            LogManager.DoLogOperation("[DEBUG] Select Application");
            rc = this.SelectApplication(0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'SelectApplication' {0} command failed - rc= {1:X}\t", 0x000000, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* Authentificate ISO */
            LogManager.DoLogOperation("[DEBUG] Authentificate TDES with master key");
            rc = this.AuthenticateAes(KeyId, AesKeyMaster);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'Authenticate' {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* Authentificate */
            LogManager.DoLogOperation("[DEBUG] Change master key to AES");
            rc = this.ChangeKeyAes(DF_APPLSETTING2_AES, 0x00, AesKeyMaster/*AesNewKeyMaster*/, null);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKeyAes' {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation("[DEBUG] Authentificate AES with master key");
            rc = this.AuthenticateAes(KeyId, AesKeyMaster/*AesNewKeyMaster*/);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'Authenticate' {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            return true;
        }
        #endregion

        #region PICCDAMKEY
        public bool LoadPICCDAMKeys()
        {
            long rc = 0;
            byte KeyId = 0x00;

            //ResetPICCDAMKeys(); return true;
            /* select Desfire master application */
            LogManager.DoLogOperation("[DEBUG] Select Application");
            rc = this.SelectApplication(0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'SelectApplication' {0} command failed - rc= {1:X}\t", 0x000000, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* Authentificate AES */
            LogManager.DoLogOperation("[DEBUG] Authentificate AES with master key");
            rc = this.AuthenticateAes(KeyId, AesKeyMaster);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'Authenticate' {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            
            rc = this.ChangeKeyAes(0x10, 0x00, DAMAuthKey, TransportKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKeyAes PICCDAMAuthKey' {0} command failed - rc= {1:X}", 0x01, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            
            rc = this.ChangeKeyAes(0x11, 0x00, DAMMACKey, TransportKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKeyAes PICCDAMAuthKey' {0} command failed - rc= {1:X}", 0x01, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            
            rc = this.ChangeKeyAes(0x12, 0x00, DAMENCKey, TransportKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKeyAes PICCDAMAuthKey' {0} command failed - rc= {1:X}", 0x01, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            return true;

        }
        /// <summary>
        /// Use for demo to reset PICCDAMKEYS.
        /// </summary>
        /// <returns></returns>
        public bool ResetPICCDAMKeys()
        {
            long rc = 0;
            byte KeyId = 0x00;
            /* select Desfire master application */
            LogManager.DoLogOperation("[DEBUG] Select Application");
            rc = this.SelectApplication(0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'SelectApplication' {0} command failed - rc= {1:X}\t", 0x000000, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* les clefs sont le résultat de la diversification entre uid 042E5A7A6E4D80 et clef diversification 0x00112233445566778899101112131415 */
            /* ces valeurs sont fixes pour la démonstration, dans votre cas il faudra utiliser les valeurs generees lors du loadkey */
            byte[] PICCDAMAuthKey = new byte[] { 0x72, 0x47, 0x9B, 0xFE, 0xD6, 0x4F, 0x7D, 0x71, 0x2C, 0x3B, 0x52, 0x8E, 0xEF, 0x82, 0x61, 0x7F };
            byte[] PICCDAMEncKey = new byte[] { 0x85, 0x28, 0x2E, 0xB6, 0x16, 0x78, 0x5C, 0xF5, 0xD9, 0x19, 0xE5, 0x56, 0x58, 0x4B, 0xC5, 0xE7 };
            byte[] PICCDAMMACKey = new byte[] { 0xE2, 0xD7, 0x21, 0x7C, 0xC8, 0xB4, 0xC2, 0x87, 0xC1, 0x69, 0x56, 0x8E, 0x92, 0xA3, 0x7A, 0x7D };

            /* Authentificate AES with master key*/
            LogManager.DoLogOperation("[DEBUG] Authentificate AES with master key");
            rc = this.AuthenticateAes(0x00, AesKeyMaster);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'Authenticate' {0} command failed - rc= {1:X}", KeyId, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /*
            [INFO] PICCDAMAuthKey 72479BFED64F7D712C3B528EEF82617F ...
            [INFO] PICCDAMEncKey 85282EB616785CF5D919E556584BC5E7 ...
            [INFO] PICCDAMMACKey E2D7217CC8B4C287C169568E92A37A7D ...
            */
            /* we need previous key to reset PICCDAMKEYs */
            rc = this.ChangeKeyAes(0x10, 0x00, TransportKey, PICCDAMAuthKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKeyAes PICCDAMAuthKey' {0} command failed - rc= {1:X}", 0x01, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }          
            rc = this.ChangeKeyAes(0x11, 0x00, TransportKey, PICCDAMMACKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKeyAes PICCDAMAuthKey' {0} command failed - rc= {1:X}", 0x01, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            rc = this.ChangeKeyAes(0x12, 0x00, TransportKey, PICCDAMEncKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKeyAes PICCDAMAuthKey' {0} command failed - rc= {1:X}", 0x01, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }


            return true;

        }

        public bool CreateDammacRequest()
        {
            long rc;
            uint pdwFreeBytes = 0;

            /* select master application */
            rc = this.SelectApplication(0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'SelectApplication' DAMAuthKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* Authentification via PICCDAMAuthKey */
            rc = this.AuthenticateAes(0x10, DAMAuthKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'AuthenticateAes' DAMAuthKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* read rest of memory for information */
            this.GetFreeMemory(ref pdwFreeBytes);
            LogManager.DoLogOperation(string.Format("DesfireEv2 'FreeMem' {0}", pdwFreeBytes));

            JsonRequest.create_dammac_json("c:\\dev\\dam_request_create.json", DAMAuthKey);

            return true;
            
        }
        #endregion
        #region dam
        public bool AddDelegatedApplicationWithoutWebService()
        {
            long rc;
            uint pdwFreeBytes = 0;

            byte file_id = 0x00;

            /* communication plain text for clear access */
            byte comm_mode = DF_COMM_MODE_PLAIN;

            /* read access clear 'E' */
            /* write access '0' master key only */
            /* read/write access clear '0' */
            /* change access rights '0' master key only */
            UInt16 access_rights = 0xE000;
            UInt32 aid = 0xF58542; //0xF58540;
            UInt16 damSlotNo = 0x0000;
            byte damSlotVersion = 0xFF;
            UInt16 quotaLimit = 0x0010;

            ushort iso_df_id = 0x1000;
            byte[] iso_df_name = new byte[] { 0xA0, 0x00, 0x00, 0x06, 0x14, 0x04, 0xF5, 0x85, 0x42 };
            /* AppKeySettings changeable, App master key changeable*/
            byte KS1 = 0x0B;
            /* AES, 3 keys, Use of 2 byte ISO/IEC 7816-4 File Identifiers*/
            byte KS2 = 0xA3;

            byte KS3 = 0x00;
            byte aksVersion = 0x00;
            byte noKeySet = 0x00;
            byte maxKeySize = 0x00;
            byte RollKey = 0x00;
            /* default key used for creation of delegated application */
            byte[] DamDefaultKey = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte DamDefaultKeyVersion = 0x00;

            LogManager.DoLogOperation(string.Format("--- Create Delegated application ---"));
            
            this.IsoWrapping(DF_ISO_WRAPPING_CARD);

            /* select master application */
            rc = this.SelectApplication(0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'SelectApplication' DAMAuthKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            #region create_dam
            /* Authentification via PICCDAMAuthKey */
            rc = this.AuthenticateAes(0x10, DAMAuthKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'AuthenticateAes' DAMAuthKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* read rest of memory for information */            
            this.GetFreeMemory(ref pdwFreeBytes);
            LogManager.DoLogOperation(string.Format("DesfireEv2 'FreeMem' {0}", pdwFreeBytes));


            /* 
             * start of issuer card job 
             */

            /*Calculate EncK*/
            byte[] EncK = this.Calc_EncK(DAMENCKey, DamDefaultKey, DamDefaultKeyVersion);

            /* Calculate DAMMAC */
            byte[] dammac = this.Calc_DAMMAC(
                DAMMACKey,
                Desfire.DF_CREATE_DELEGATED_APPLICATION,
                aid, damSlotNo, damSlotVersion, quotaLimit, KS1, KS2,
                KS3, aksVersion, noKeySet, maxKeySize, RollKey, 
                iso_df_id, iso_df_name,
                EncK);

            /*
             * stop of issuer card job 
             */

            /* Authentification via PICCDAMAuthKey */
            rc = this.AuthenticateAes(0x10, DAMAuthKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'AuthenticateAes' DAMAuthKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* 
             * start of application provider job 
             */

            /* Create Delegated application */
            rc = this.CreateIsoDelegatedApplication(
                aid, damSlotNo, damSlotVersion, quotaLimit, KS1, KS2, 
                KS3, aksVersion, noKeySet, maxKeySize, RollKey, 
                iso_df_id, iso_df_name, iso_df_name.Length, 
                EncK, dammac);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'CreateDelegatedApplication' command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            #endregion //create_dam

            /* read rest of memory for information */
            this.GetFreeMemory(ref pdwFreeBytes);
            LogManager.DoLogOperation(string.Format("DesfireEv2 'FreeMem' {0}", pdwFreeBytes));


            /* select DAM application */
            rc = this.SelectApplication(aid);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'SelectApplication' Delegated command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            #region authenticate_default_dam_key
            /* Authentification via  DamDefaultKey temporary key */
            rc = this.AuthenticateAes(0x00, DamDefaultKey); 
            if (rc != SCARD.S_SUCCESS)
            {
            LogManager.DoLogOperation(string.Format("DesfireEv2 'AuthenticateAes' DamDefaultKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
            return false;
            }
            #endregion authenticate_default_dam_key

            #region change_app_key

            LogManager.DoLogOperation("DesfireEv2 check key settings");
            byte key_settings = 0x00;
            byte key_count = 0x00;
            rc = this.GetKeySettings(ref key_settings, ref key_count);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'GetKeySettings' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation(string.Format("DesfireEv2 key_settings {0:X} key_count {1:X}", key_settings, key_count));
            /*Delegated applications can be deleted permanently using Cmd.DeleteApplication. If b2 of PICCKeySettings is set to 0 */
            key_settings &= 0xFD;
            rc = this.ChangeKeySettings(key_settings);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'GetKeySettings' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            rc = this.GetKeySettings(ref key_settings, ref key_count);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'GetKeySettings' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation(string.Format("DesfireEv2 key_settings {0:X} key_count {1:X}", key_settings, key_count));

            byte[] DefaultKey = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] AppMasterKey1 = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
            byte[] AppMasterKey2 = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
            byte[] AppMasterKey3 = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 };

            LogManager.DoLogOperation("DesfireEv2 'ChangeKeyAes' APP master key");
            rc = this.ChangeKeyAes( 0x00, 0x01, AppMasterKey1, null);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKey' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation("DesfireEv2 'Check Authentificate AES with master App key");
            rc = this.AuthenticateAes(0x00, AppMasterKey1);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'Authenticate' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation("DesfireEv2 'ChangeKeyAes' Key 1");
            rc = this.ChangeKeyAes(0x01, 0x02, AppMasterKey2, DefaultKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKey' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation("DesfireEv2 'ChangeKeyAes' Key 2");
            rc = this.ChangeKeyAes(0x02, 0x03, AppMasterKey3, DefaultKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKey' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
           
            #endregion //change_app_key

            byte[] provider_data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

            /* Create Sample Standards files */
            LogManager.DoLogOperation("DesfireEv2 Provider create Standard file");

            rc = this.CreateIsoStdDataFile(file_id, 0x1001, comm_mode, access_rights, (uint)provider_data.Length);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'CreateStdDataFile' Sample command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            /* write data inside file */
            
            LogManager.DoLogOperation("DesfireEv2 Provider write its data");
            rc = this.WriteData(file_id, comm_mode, 0, (uint)provider_data.Length, provider_data);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'WriteData' Sample command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* read data from file */
            uint done = 0;
            byte[] local = new byte[1024];

            LogManager.DoLogOperation("DesfireEv2 Provider read its data");

            rc = this.ReadData(file_id, comm_mode, 0, 0, ref local, ref done);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'ReadData' Sample command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation(BinConvert.ToHex(local, done));
            /* 
             * end of application provider job 
             */


            /*
             * check delegated application creation
             */
              /* select master application */
            rc = this.SelectApplication(0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'SelectApplication' DAMAuthKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* Retrieve DAM slot information */
            byte dam_slot_version = 0;
            byte quota_limit = 0;
            byte free_blocks = 0;

            rc = this.GetDelegatedInfo(damSlotNo, ref aid, ref dam_slot_version, ref quota_limit, ref free_blocks);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("Desfire 'GetDelegatedInfo'command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation(string.Format("--- Application {0:X} version {1:X} quota {2:X} free_blocks {3:X} ---", aid, dam_slot_version, quota_limit, free_blocks));


            return true;
        }
        public bool AddDelegatedApplication()
        {
            long rc;
            uint pdwFreeBytes = 0;

            byte file_id = 0x00;

            /* communication plain text for clear access */
            byte comm_mode = DF_COMM_MODE_PLAIN;

            /* read access clear 'E' */
            /* write access '0' master key only */
            /* read/write access clear '0' */
            /* change access rights '0' master key only */
            UInt16 access_rights = 0xE000;
            UInt32 aid = 0xF58542;

            UInt16 damSlotNo = 0x0000;
            byte damSlotVersion = 0xFF;
            UInt16 quotaLimit = 0x0010;
            ushort iso_df_id = 0x1000;
            byte[] iso_df_name = new byte[] { 0xA0, 0x00, 0x00, 0x06, 0x14, 0x04, 0xF5, 0x85, 0x40 };
            /* AppKeySettings changeable, App master key changeable*/
            byte KS1 = 0x0B;
            /* AES, 3 keys, Use of 2 byte ISO/IEC 7816-4 File Identifiers*/
            byte KS2 = 0xA3;

            byte KS3 = 0x00;
            byte aksVersion = 0x00;
            byte noKeySet = 0x00;
            byte maxKeySize = 0x00;
            byte RollKey = 0x00;
            /* default key used for creation of delegated application */
            byte[] DamDefaultKey = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            LogManager.DoLogOperation(string.Format("--- Create Delegated application ---"));

            this.IsoWrapping(DF_ISO_WRAPPING_CARD);

            /* select master application */
            rc = this.SelectApplication(0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'SelectApplication' DAMAuthKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

#region create_dam
            /* Authentification via PICCDAMAuthKey */
            rc = this.AuthenticateAes(0x10, DAMAuthKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'AuthenticateAes' DAMAuthKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* read rest of memory for information */
            this.GetFreeMemory(ref pdwFreeBytes);
            LogManager.DoLogOperation(string.Format("DesfireEv2 'FreeMem' {0}", pdwFreeBytes));


            /* Retrieve DAM slot information */
            byte dam_slot_version = 0;
            byte quota_limit = 0;
            byte free_blocks = 0;

            rc = this.GetDelegatedInfo(damSlotNo, ref aid, ref dam_slot_version, ref quota_limit, ref free_blocks);
            if (rc == SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("--- Application {0:X} version {1:X} quota {2:X} free_blocks {3:X} ---", aid, dam_slot_version, quota_limit, free_blocks));
            }

            /* 
             * start of application provider job 
             */

            /* Create Delegated application */
            rc = this.CreateIsoDelegatedApplication(
                aid, damSlotNo, damSlotVersion, quotaLimit, KS1, KS2,
                KS3, aksVersion, noKeySet, maxKeySize, RollKey,
                iso_df_id, iso_df_name, iso_df_name.Length,
                EncK, DAMMAC);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'CreateDelegatedApplication' command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

#endregion //create_dam

            /* read rest of memory for information */
            this.GetFreeMemory(ref pdwFreeBytes);
            LogManager.DoLogOperation(string.Format("DesfireEv2 'FreeMem' {0}", pdwFreeBytes));


            /* select DAM application */
            rc = this.SelectApplication(aid);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'SelectApplication' Delegated command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

#region authenticate_default_dam_key
            /* Authentification via  DamDefaultKey temporary key */
            rc = this.AuthenticateAes(0x00, DamDefaultKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'AuthenticateAes' DamDefaultKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
#endregion authenticate_default_dam_key

#region change_app_key

            LogManager.DoLogOperation("DesfireEv2 check key settings");
            byte key_settings = 0x00;
            byte key_count = 0x00;
            rc = this.GetKeySettings(ref key_settings, ref key_count);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'GetKeySettings' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation(string.Format("DesfireEv2 key_settings {0:X} key_count {1:X}", key_settings, key_count));
            /*Delegated applications can be deleted permanently using Cmd.DeleteApplication. If b2 of PICCKeySettings is set to 0 */
            key_settings &= 0xFD;
            rc = this.ChangeKeySettings(key_settings);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'GetKeySettings' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            rc = this.GetKeySettings(ref key_settings, ref key_count);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'GetKeySettings' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation(string.Format("DesfireEv2 key_settings {0:X} key_count {1:X}", key_settings, key_count));

            byte[] DefaultKey = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] AppMasterKey1 = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
            byte[] AppMasterKey2 = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
            byte[] AppMasterKey3 = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 };

            LogManager.DoLogOperation("DesfireEv2 'ChangeKeyAes' APP master key");
            rc = this.ChangeKeyAes(0x00, 0x01, AppMasterKey1, null);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKey' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation("DesfireEv2 'Check Authentificate AES with master App key");
            rc = this.AuthenticateAes(0x00, AppMasterKey1);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'Authenticate' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation("DesfireEv2 'ChangeKeyAes' Key 1");
            rc = this.ChangeKeyAes(0x01, 0x02, AppMasterKey2, DefaultKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKey' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation("DesfireEv2 'ChangeKeyAes' Key 2");
            rc = this.ChangeKeyAes(0x02, 0x03, AppMasterKey3, DefaultKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ChangeKey' command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

#endregion //change_app_key

            byte[] provider_data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

            /* Create Sample Standards files */
            LogManager.DoLogOperation("DesfireEv2 Provider create Standard file");

            rc = this.CreateIsoStdDataFile(file_id, 0x1001, comm_mode, access_rights, (uint)provider_data.Length);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'CreateStdDataFile' Sample command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            /* write data inside file */

            LogManager.DoLogOperation("DesfireEv2 Provider write its data");
            rc = this.WriteData(file_id, comm_mode, 0, (uint)provider_data.Length, provider_data);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'WriteData' Sample command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* read data from file */
            uint done = 0;
            byte[] local = new byte[1024];

            LogManager.DoLogOperation("DesfireEv2 Provider read its data");

            rc = this.ReadData(file_id, comm_mode, 0, 0, ref local, ref done);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'ReadData' Sample command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            LogManager.DoLogOperation(BinConvert.ToHex(local, done));
            /* 
             * end of application provider job 
             */


            /*
             * check delegated application creation
             */
            /* select master application */
            rc = this.SelectApplication(0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("DesfireEv2 'SelectApplication' DAMAuthKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* Retrieve DAM slot information */
            dam_slot_version = 0;
            quota_limit = 0;
            free_blocks = 0;

            rc = this.GetDelegatedInfo(damSlotNo, ref aid, ref dam_slot_version, ref quota_limit, ref free_blocks);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("Desfire 'GetDelegatedInfo' command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation(string.Format("--- Application {0:X} version {1:X} quota {2:X} free_blocks {3:X} ---", aid, dam_slot_version, quota_limit, free_blocks));


            return true;
        }
        /// <summary>
        /// Free DAM AID memory. The content of the DAM AID (file, cyclic record ...).
        /// </summary>
        /// <returns></returns>
        public bool FormatDelegatedApplication()
        {
            long rc;
            uint pdwFreeBytes = 0;

            LogManager.DoLogOperation(string.Format("--- Format Delegated application ---"));

            this.IsoWrapping(DF_ISO_WRAPPING_CARD);

            /* select master application */
            rc = this.SelectApplication(0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation("Failed to SelectApplication 000000.");
                return false;
            }

            /* Authentification via PICCDAMAuthKey */
            rc = this.AuthenticateAes(0x10, DAMAuthKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("Desfire 'AuthenticateAes' DAMAuthKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            this.GetFreeMemory(ref pdwFreeBytes);
            LogManager.DoLogOperation(string.Format("[DEBUG] Desfire FreeMem' {0}", pdwFreeBytes));

            /* Retrieve DAM slot information */
            UInt32 aid = 0;
            UInt16 damSlotNo = 0x0000;

            byte dam_slot_version = 0;
            byte quota_limit = 0;
            byte free_blocks = 0;

            rc = this.GetDelegatedInfo(damSlotNo, ref aid, ref dam_slot_version, ref quota_limit, ref free_blocks);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("Desfire 'GetDelegatedInfo' command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation(string.Format("--- Application {0:X} version {1:X} quota {2:X} free_blocks {3:X} ---", aid, dam_slot_version, quota_limit, free_blocks));

            rc = this.SelectApplication(aid);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("Failed to SelectApplication - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            rc = this.AuthenticateAes(0x00, AesKeyMaster);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("Desfire 'AuthenticateAes' AppMasterKey1 command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            
            rc = this.FormatDAM();
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("Desfire 'DeleteApplication' {0} command failed - rc= {1:X}\t", aid, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            /* select master application */
            rc = this.SelectApplication(0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation("Failed to SelectApplication 000000.");
                return false;
            }

            /* Authentification via PICCDAMAuthKey */
            rc = this.AuthenticateAes(0x10, DAMAuthKey);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("Desfire 'AuthenticateAes' DAMAuthKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            this.GetFreeMemory(ref pdwFreeBytes);
            LogManager.DoLogOperation(string.Format("[DEBUG] Desfire FreeMem' {0}", pdwFreeBytes));

            rc = this.GetDelegatedInfo(damSlotNo, ref aid, ref dam_slot_version, ref quota_limit, ref free_blocks);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("Desfire 'GetDelegatedInfo' command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation(string.Format("--- Application {0:X} version {1:X} quota {2:X} free_blocks {3:X} ---", aid, dam_slot_version, quota_limit, free_blocks));


            return true;
        }
        /// <summary>
        /// Erase DAM AID from the list.
        /// </summary>
        /// <returns></returns>
        public bool EraseDelegatedApplication()
        {
            long rc;
            uint pdwFreeBytes = 0;
            UInt32 aid =  0xF58541;
            LogManager.DoLogOperation(string.Format("--- Erase Delegated application ---"));

            this.IsoWrapping(DF_ISO_WRAPPING_CARD);

            /* select master application */
            rc = this.SelectApplication( 0x000000);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation("Failed to SelectApplication 000000.");
                return false;
            }

            /* Authentification via App DAM master key */
            rc = this.AuthenticateAes(0x00, AesKeyMaster);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("Desfire 'AuthenticateAes' DAMAuthKey command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            this.GetFreeMemory(ref pdwFreeBytes);
            LogManager.DoLogOperation(string.Format("[DEBUG] Desfire FreeMem' {0}", pdwFreeBytes));

            /* Retrieve DAM slot information */
            aid = 0;
            UInt16 damSlotNo = 0x0000;

            byte dam_slot_version = 0;
            byte quota_limit = 0;
            byte free_blocks = 0;

            rc = this.GetDelegatedInfo(damSlotNo, ref aid, ref dam_slot_version, ref quota_limit, ref free_blocks);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("Desfire 'GetDelegatedInfo' command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation(string.Format("--- Application {0:X} version {1:X} quota {2:X} free_blocks {3:X} ---", aid, dam_slot_version, quota_limit, free_blocks));

            rc = this.DeleteApplication(aid);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("Desfire 'DeleteApplication' {0} command failed - rc= {1:X}\t", aid , (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            this.GetFreeMemory(ref pdwFreeBytes);
            LogManager.DoLogOperation(string.Format("[DEBUG] Desfire FreeMem' {0}", pdwFreeBytes));

            rc = this.GetDelegatedInfo(damSlotNo, ref aid, ref dam_slot_version, ref quota_limit, ref free_blocks);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("Desfire 'GetDelegatedInfo' command failed - rc= {0:X}\t", (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }
            LogManager.DoLogOperation(string.Format("--- Application {0:X} version {1:X} quota {2:X} free_blocks {3:X} ---", aid, dam_slot_version, quota_limit, free_blocks));


            return true;
        }
#endregion //dam
#region openssl
        private bool call_openssl(List<string> sign_args, Console_OpenSsl.ActionOpenSsl action)
        {
            Console_OpenSsl ops = new Console_OpenSsl();
            string args_openssl = ops.CreateArguments(action, sign_args);

            LogManager.DoLogOperation(args_openssl);
            if (args_openssl == null)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Openssl Arguments are not correct"));
                return false;
            }
            _error_openssl = false;
            openssl_message = "";
            ops.procErrorDataReceived += onErrorDataReceived;
            ops.procOutputDataReceived += onOutputDataReceived;
            ops.procExit += onExited;
            /* Install */
            ops.InitializeMyProcess();
            ops.InitializeMyProcessStartInfo(args_openssl);
            ops.StartProcess();

            if (wait_process_end.WaitOne(5000) == false)
            {
                LogManager.DoLogOperation("[DEBUG] OpenSsl fails to wait end of process !!!");
                return false;
            }
            return true;
        }
        private void onOutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                _error_openssl = true;
                this.ConcatenateConsoleMessage(e.Data);
            }
        }

        private void onErrorDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                LogManager.DoLogOperation("[ERROR]" + e.Data);
            }
        }

        private void onExited(object sender, EventArgs e)
        {
            //
            wait_process_end.Set();
            LogManager.DoLogOperation("[DEBUG] OpenSsl Process ended.");
        }

        private void ClearConsoleMessage(string str_)
        {
            if (str_ != null)
                LogManager.DoLogOperation("[DEBUG] [CLEAR]" + str_);
        }

        private void ConcatenateConsoleMessage(string str_)
        {
            /* feedback data from openssl when command succeeded */
            if (str_ != null)
            {
                LogManager.DoLogOperation("[DEBUG] [SUM]" + str_);
                openssl_message += str_;
            }
        }

#endregion

        
    }
}
