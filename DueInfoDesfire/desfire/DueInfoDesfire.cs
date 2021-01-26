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

namespace DueInfo.desfire
{
    public class DueInfoDesfire : Desfire
    {

        public byte[] AesKeyMaster { get; set; }
        public byte[] AesKeyDueInfo { get; set; }
        public byte[] Escn { get; set; }

        protected byte[] AesKeyDiversified = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        private byte[] TransportKey = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

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
        string cert_dueinfo_der_file = "pem\\ca.dueinfo.cert.der";
        string cert_pem_file = "pem\\ca.intermediate.cert.pem";

        public DueInfoDesfire(ICardTransmitter transmitter, byte isoWrapping = 0) : base(transmitter, isoWrapping)
        {

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
            LogManager.DoLogOperation("[DEBUG] Authentificate with master key");
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
                    if(sourceFile.Length == 0)
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
            //rc = this.CreateStdDataFile(file_id, comm_mode, access_rights, (uint)Escn.Length);CreateIsoStdDataFile
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
            //rc = this.CreateStdDataFile(file_id, comm_mode, access_rights, (uint)cert.Length);
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
            rc = this.ChangeKeyAes( 0x01, 0x01, AesKeyDiversified, TransportKey);
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
        public bool Read( ref byte[] escn, ref byte[] sign, ref byte[] cert)
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
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'ReadData' SIGNATURE command failed - rc= {0:X}", (0xFFFF - (0xFFFF + rc + 1000))));
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
#if _SELP
            byte[] test = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            rc = this.AuthenticateAes(0x00, test);
            if (rc != SCARD.S_SUCCESS)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Desfire 'Authenticate' {0} command failed - rc= {1:X}", 0x00, (0xFFFF - (0xFFFF + rc + 1000))));
                return false;
            }

            //
            DueInfo.Diversification.Diversification_AES128(escn, AesKeyDueInfo, AesKeyDueInfo.Length, ref AesKeyDiversified);
            LogManager.DoLogOperation("SELP ESCN " + BinConvert.ToHex(escn));
            LogManager.DoLogOperation("SELP RES  " + BinConvert.ToHex(AesKeyDiversified));

#else
            DueInfo.Diversification.Diversification_AES128(AesKeyDueInfo, escn, escn.Length, ref AesKeyDiversified);
#endif
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
            
            /* Authentificate for diversification only */
            LogManager.DoLogOperation("[DEBUG] Authentificate with UID Diversified key");
#if _SELP
            DueInfo.Diversification.Diversification_AES128(uid, AesKeyDueInfo, AesKeyDueInfo.Length, ref AesKeyDiversified);

#else
            DueInfo.Diversification.Diversification_AES128(AesKeyDueInfo, uid, uid.Length, ref AesKeyDiversified);
#endif


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
            List<string> sign_args = new List<string>();

            /* convert der certificate to pem */
            LogManager.DoLogOperation("[DEBUG] OpenSsl convert certificate from der to pem");

            sign_args.Add(cert_dueinfo_der_file);
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
            //sign_args.Add("test");
            sign_args.Add(pub_key_file);
            sign_args.Add(sign_file);
            sign_args.Add(escn_data);
            if (call_openssl(sign_args, Console_OpenSsl.ActionOpenSsl.actSignVerify) == false)
            {
                return false;
            }
            sign_args.Clear();

#if _0
            /* convert der certificate to pem */
            LogManager.DoLogOperation("[DEBUG] OpenSsl convert certificate from der to pem");
            
            sign_args.Add(cert_der_file);
            sign_args.Add(cert_pem_file);
            if( call_openssl(sign_args, Console_OpenSsl.ActionOpenSsl.actDerToPem) == false)
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
#endif
            return true;

        }
#region openssl
        private bool call_openssl(List<string> sign_args, Console_OpenSsl.ActionOpenSsl action)
        {
            Console_OpenSsl ops = new Console_OpenSsl();
            string args_openssl = ops.CreateArguments(action, sign_args);

            
            if (args_openssl == null)
            {
                LogManager.DoLogOperation(string.Format("[DEBUG] Openssl Arguments are not correct"));
                return false;
            }
            LogManager.DoLogOperation(args_openssl);

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
