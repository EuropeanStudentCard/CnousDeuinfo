using DueInfo.desfireev2;
using SpringCard.LibCs;
using SpringCard.PCSC;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Windows.Forms;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using DueInfoDesfireEV2;

namespace DueInfo
{
    class Program : ISynchronizeInvoke
    {
        #region error_type
        const int ERROR_NO_ERROR = 0;
        const int ERROR_PARSE_ERROR = 1;
        const int ERROR_READER_ERROR = 2;
        const int ERROR_INSERT_CARD = 3;
        const int ERROR_EJECT_CARD = 4;
        const int ERROR_ERASE_CARD = 5;
        const int ERROR_WRITE_CARD = 6;
        const int ERROR_READ_CARD = 7;
        #endregion

        #region actions
        static ActionToDo _actions_to_do = 0x0000;
        public enum ActionToDo
        {
            actNone = 0x0000,
            actNew = 0x0001,
            actDisable = 0x0002,
            actRead = 0x0004,
            actCheck = 0x0008,
            actList = 0x0010,
            actPause = 0x0020,
            actDiversification = 0x0080,
            actFormat = 0x0100,
            actLoadMasterKey = 0x0200,
            actNewDam = 0x0400,
            actEraseDam = 0x0800,
            actDammac = 0x1000,
            actNewDamAlone = 0x2000,
            actFreeDam = 0x4000,
        };

        const int MAX_ACTION_COUNTER = 10;
        static string[] Actions = new string[MAX_ACTION_COUNTER];
#endregion

        static private List<string> m_ReaderList;
        static private int _reader_id = -1;
        static private SCardChannel m_hCard = null;
        static private byte m_isoWrapping = 0;
        static private DueInfoDesfireEv2 m_Desfire;

        static private string _aes_owner_divert_root_key;

        static private string _aes_base_key;
        static private string _aes_master_key;
        //static private string _aes_new_master_key;
        static private string _card_uid;
        static private string _escn_id;
        static private string _dam_auth_key;
        static private string _dam_mac_key;
        static private string _dam_enc_key;
        static private string _dam_enck;
        static private string _dam_dammac;

        static byte[] _escn;
        static byte[] _signature;
        static byte[] _certificate;
        static private bool _iso_enable;

        static int Main(string[] args)
        {
            LogManager.InstantiateLogManager();
            _aes_master_key = "";
            //_aes_new_master_key = "";
            _aes_base_key = "";
            _aes_owner_divert_root_key = "";
            _iso_enable = false;
            Logger.ReadArgs(args);

            //Logger.ConsoleLevel = Logger.Level.Info;
            Console.Title = string.Format("{0} {1} v.{2}", Application.CompanyName, Application.ProductName, Application.ProductVersion);

            if (args.Length > 0)
            {
                if (!ParseArgs(args))
                {
                    LogManager.DoLogOperation("[ERROR] Fails to parse argument !!!");

                    Console.WriteLine("Hit any key to exit.");
                    Console.ReadKey();
                    return ERROR_PARSE_ERROR;
                }
            }
            else
            {
                goto done;
            }


        done:

            m_ReaderList = new List<string>();
            int i = 0;

            if (SCARD.Readers == null)
            {
                return ERROR_READER_ERROR;
            }
            for (i = 0; i < SCARD.Readers.Length - 1; i++)
            {
                m_ReaderList.Add(SCARD.Readers[i]);
            }

            if (SCARD.Readers.Length == 0)
            {
                LogManager.DoLogOperation("[ERROR] No PCSC reader available !!!");
                return ERROR_READER_ERROR;
            }
            m_ReaderList.Add(SCARD.Readers[SCARD.Readers.Length - 1]);

#region format
            if ((_actions_to_do & ActionToDo.actFormat) != 0)
            {
                LogManager.DoLogOperation("[INFO] Formatting Desfire Card...");
                if (_reader_id == -1)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a reader. Add --reader=X to console command.");
                    return ERROR_READER_ERROR;
                }

                if (_aes_master_key.Length != 32)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a base key. Add --master-key=XXXX...X to console command.");
                    return ERROR_PARSE_ERROR;
                }
                if (InsertCard() == ERROR_NO_ERROR)
                {
                    m_isoWrapping = DueInfoDesfireEv2.DF_ISO_WRAPPING_CARD;
                    m_Desfire = new DueInfoDesfireEv2(m_hCard, m_isoWrapping);

                    m_Desfire.AesKeyMaster = BinConvert.HexToBytes(_aes_master_key);
                    if (m_Desfire.Format())
                    {
                        LogManager.DoLogOperation("[INFO] DUEINFO Done ...");
                    }

                    EjectCard();
                }
            }
#endregion

#region new
            if ((_actions_to_do & ActionToDo.actNew) != 0)
            {
                LogManager.DoLogOperation("[INFO] Creating new DUEINFO Desfire Card...");
                if (_reader_id == -1)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a reader. Add --reader=X to console command.");
                    return ERROR_READER_ERROR;
                }

                if (_aes_base_key.Length != 32)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set DUEINFO base key for diversification. Add --dueinfo-key=XXXX...X to console command.");
                    return ERROR_PARSE_ERROR;
                }

                if (_aes_master_key.Length != 32)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a base key. Add --master-key=XXXX...X to console command.");
                    return ERROR_PARSE_ERROR;
                }

                if (InsertCard() == ERROR_NO_ERROR)
                {
                    m_isoWrapping = DueInfoDesfireEv2.DF_ISO_WRAPPING_CARD;
                    m_Desfire = new DueInfoDesfireEv2(m_hCard, m_isoWrapping);

                    m_Desfire.AesKeyMaster = BinConvert.HexToBytes(_aes_master_key);
                    //m_Desfire.AesNewKeyMaster = BinConvert.HexToBytes(_aes_new_master_key);
                    m_Desfire.AesKeyDueInfo = BinConvert.HexToBytes(_aes_base_key);
                    m_Desfire.Escn = BinConvert.HexToBytes(_escn_id);
                    if (m_Desfire.Create())
                    {
                        LogManager.DoLogOperation("[INFO] DUEINFO Done ...");
                    }

                    EjectCard();
                }

            }
#endregion
#region erase
            else if ((_actions_to_do & ActionToDo.actDisable) != 0)
            {
                LogManager.DoLogOperation("[INFO] Erasing DUEINFO Desfire Card...");
                if (_reader_id == -1)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a reader. Add --reader=X to console command.");
                    return ERROR_READER_ERROR;
                }
                if (InsertCard() == ERROR_NO_ERROR)
                {
                    m_isoWrapping = DueInfoDesfireEv2.DF_ISO_WRAPPING_CARD;
                    m_Desfire = new DueInfoDesfireEv2(m_hCard, m_isoWrapping);

                    if (_aes_master_key.Length == 32)
                    {
                        m_Desfire.AesKeyMaster = BinConvert.HexToBytes(_aes_master_key);

                        if (m_Desfire.Disable())
                        {
                            LogManager.DoLogOperation("[INFO] DUEINFO is disabled ...");
                        }
                    }

                    EjectCard();
                }
            }
#endregion

#region read
            else if ((_actions_to_do & ActionToDo.actRead) != 0)
            {
                LogManager.DoLogOperation("[INFO] Reading DUEINFO Desfire Card...");
                if (_reader_id == -1)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a reader. Add --reader=X to console command.");
                    return ERROR_READER_ERROR;
                }
                if (InsertCard() == ERROR_NO_ERROR)
                {
                    if (_iso_enable == false)
                    {
                        m_isoWrapping = DueInfoDesfireEv2.DF_ISO_WRAPPING_CARD;
                        m_Desfire = new DueInfoDesfireEv2(m_hCard, m_isoWrapping);

                        if (m_Desfire.Read(ref _escn, ref _signature, ref _certificate))
                        {
                            LogManager.DoLogOperation("[INFO] Read Done ...");
                        }
                    }
                    else
                    {
                        if (Iso_Read(ref _escn, ref _signature, ref _certificate))
                        {
                            LogManager.DoLogOperation("[INFO] Read Done ...");
                        }
                    }

                    EjectCard();
                }
            }
#endregion

#region check
            else if ((_actions_to_do & ActionToDo.actCheck) != 0)
            {
                LogManager.DoLogOperation("[INFO] Checking DUEINFO Desfire Card...");

                if (_reader_id == -1)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a reader. Add --reader=X to console command.");
                    return ERROR_READER_ERROR;
                }

                /* read data from card */
                if (InsertCard() == ERROR_NO_ERROR)
                {
                    m_isoWrapping = DueInfoDesfireEv2.DF_ISO_WRAPPING_CARD;
                    m_Desfire = new DueInfoDesfireEv2(m_hCard, m_isoWrapping);
                    m_Desfire.AesKeyDueInfo = BinConvert.HexToBytes(_aes_base_key);

                    if (m_Desfire.Read(ref _escn, ref _signature, ref _certificate))
                    {
                        LogManager.DoLogOperation("[INFO] Read Done ...");
                        if (m_Desfire.Check(_escn, _signature, _certificate))
                        {
                            LogManager.DoLogOperation("[INFO] Card is from DUEINFO ...");
                        }
                        else
                        {
                            LogManager.DoLogOperation("ERROR Card is out of DUEINFO ...");
                        }
                    }

                    EjectCard();
                }
            }
#endregion
#region diversification
            else if ((_actions_to_do & ActionToDo.actDiversification) != 0)
            {
                LogManager.DoLogOperation("[INFO] Check AES 128 diversification...");

                if (_aes_base_key.Length != 32)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a base key. Add --base=XXXX...X to console command.");
                    return ERROR_READER_ERROR;
                }
                if (_escn_id.Length == 0)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set ESCn. Add --escn=XX.. to console command.");
                    return ERROR_READER_ERROR;
                }
                byte[] diversified_key = new byte[16];
                byte[] data_to_diversify = BinConvert.HexToBytes(_escn_id);
                DueInfo.Diversification.Diversification_AES128(BinConvert.HexToBytes(_aes_base_key),
                    data_to_diversify, data_to_diversify.Length, ref diversified_key);
            }
#endregion

#region load_aes_master_keys
            if ((_actions_to_do & ActionToDo.actLoadMasterKey) != 0)
            {
                LogManager.DoLogOperation("[INFO] Load Master and DAM keys...");
                if (_reader_id == -1)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a reader. Add --reader=X to console command.");
                    return ERROR_READER_ERROR;
                }

                if (_aes_master_key.Length != 32)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a base key. Add --master-key=XXXX...X to console command.");
                    return ERROR_PARSE_ERROR;
                }


                if (_aes_owner_divert_root_key.Length != 32)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a root key for diversification. Add --base=XXXX...X to console command.");
                    return ERROR_READER_ERROR;
                }

                if (_card_uid.Length == 0)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set card uid for diversification. Add --uid=XXXX...X to console command.");
                    return ERROR_READER_ERROR;
                }

                byte[] UID = BinConvert.HexToBytes(_card_uid);

                if (InsertCard() == ERROR_NO_ERROR)
                {
                    m_isoWrapping = DueInfoDesfireEv2.DF_ISO_WRAPPING_CARD;
                    m_Desfire = new DueInfoDesfireEv2(m_hCard, m_isoWrapping);

                    m_Desfire.AesKeyMaster = BinConvert.HexToBytes(_aes_master_key);

                    byte[] diversified_key = new byte[16];

                    m_Desfire.DAMAuthKey = new byte[16];// BinConvert.HexToBytes(_dam_auth_key);
                    DueInfo.Diversification.Diversification_AES128(
                        BinConvert.HexToBytes(_aes_owner_divert_root_key),
                        UID, UID.Length, ref diversified_key);
                    Array.Copy(diversified_key, 0, m_Desfire.DAMAuthKey, 0, 16);
                    LogManager.DoLogOperation("[INFO] PICCDAMAuthKey " + BinConvert.ToHex(m_Desfire.DAMAuthKey));

                    byte[] data_to_diversify = BinConvert.HexToBytes(_card_uid);
                    data_to_diversify[0] = 0x00;
                    m_Desfire.DAMENCKey = new byte[16]; //BinConvert.HexToBytes(_dam_enc_key);
                    DueInfo.Diversification.Diversification_AES128(
                       BinConvert.HexToBytes(_aes_owner_divert_root_key),
                       data_to_diversify, data_to_diversify.Length, ref diversified_key);
                    Array.Copy(diversified_key, 0, m_Desfire.DAMENCKey, 0, 16);
                    LogManager.DoLogOperation("[INFO] PICCDAMEncKey " + BinConvert.ToHex(m_Desfire.DAMENCKey));

                    data_to_diversify = BinConvert.HexToBytes(_card_uid);
                    data_to_diversify[0] = 0xFF;

                    m_Desfire.DAMMACKey = new byte[16]; //BinConvert.HexToBytes(_dam_mac_key);
                    DueInfo.Diversification.Diversification_AES128(
                       BinConvert.HexToBytes(_aes_owner_divert_root_key),
                       data_to_diversify, data_to_diversify.Length, ref diversified_key);
                    Array.Copy(diversified_key, 0, m_Desfire.DAMMACKey, 0, 16);
                    LogManager.DoLogOperation("[INFO] PICCDAMMACKey " + BinConvert.ToHex(m_Desfire.DAMMACKey));
                    
                    /* we do this to be sure that masker key is AES type, needed for PICCDAMKEY */
                    if (m_Desfire.ChangeMasterKeyToAES())
                    {
                        LogManager.DoLogOperation("[INFO] Master key set to AES ...");
                        if (m_Desfire.LoadPICCDAMKeys())
                        {
                            LogManager.DoLogOperation("[INFO] PICC DAM keys loaded ...");
                        }
                    }              

                    EjectCard();
                }

            }
            #endregion
            #region request_web
            if ((_actions_to_do & ActionToDo.actDammac) != 0)
            {
                LogManager.DoLogOperation("[INFO] Create DAMMAC...");
                if (_reader_id == -1)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a reader. Add --reader=X to console command.");
                    return ERROR_READER_ERROR;
                }
                if (_dam_auth_key.Length != 32)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set PICCDAMAUTHKEY. Add --master-key=XXXX...X to console command.");
                    return ERROR_PARSE_ERROR;
                }
                
                if (InsertCard() == ERROR_NO_ERROR)
                {
                    m_isoWrapping = DueInfoDesfireEv2.DF_ISO_WRAPPING_CARD;
                    m_Desfire = new DueInfoDesfireEv2(m_hCard, m_isoWrapping);

                    m_Desfire.DAMAuthKey = BinConvert.HexToBytes(_dam_auth_key);

                    LogManager.DoLogOperation("[INFO] Create DAMMAC ...");
                    if (m_Desfire.CreateDammacRequest())
                    {
                        
                        LogManager.DoLogOperation("[INFO] DAMMAC JSON REQUEST is created ...");
                    }

                    EjectCard();
                }
            }

            #endregion request_web
            #region dam
            if ((_actions_to_do & ActionToDo.actNewDam) != 0)
            {
                LogManager.DoLogOperation("[INFO] Create delegated application...");
                if (_reader_id == -1)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a reader. Add --reader=X to console command.");
                    return ERROR_READER_ERROR;
                }
                if (_dam_auth_key.Length != 32)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set DAMAuthKey. Add --x-damauth-key=XXXX...X to console command.");
                    return ERROR_PARSE_ERROR;
                }

                if (_dam_enck.Length == 0)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set EncK. Add --n-enck=XXXX...X to console command.");
                    return ERROR_PARSE_ERROR;
                }
                if (_dam_dammac.Length != 16)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set DAMMAC. Add --q-dammac=XXXX...X to console command.");
                    return ERROR_PARSE_ERROR;
                }


                if (InsertCard() == ERROR_NO_ERROR)
                {
                    m_isoWrapping = DueInfoDesfireEv2.DF_ISO_WRAPPING_CARD;
                    m_Desfire = new DueInfoDesfireEv2(m_hCard, m_isoWrapping);

                    m_Desfire.DAMAuthKey = BinConvert.HexToBytes(_dam_auth_key);
                    m_Desfire.EncK = BinConvert.HexToBytes(_dam_enck);
                    m_Desfire.DAMMAC = BinConvert.HexToBytes(_dam_dammac);

                    LogManager.DoLogOperation("[INFO] Create DAM ...");
                    if (m_Desfire.AddDelegatedApplication())
                    {
                        LogManager.DoLogOperation("[INFO] DAM is created ...");
                    }

                    EjectCard();
                }

            }
            if ((_actions_to_do & ActionToDo.actNewDamAlone) != 0)
            {
                LogManager.DoLogOperation("[INFO] Create delegated application alone...");
                if (_reader_id == -1)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a reader. Add --reader=X to console command.");
                    return ERROR_READER_ERROR;
                }

                if (_dam_auth_key.Length != 32)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set DAMAuthKey. Add --x-damauth-key=XXXX...X to console command.");
                    return ERROR_PARSE_ERROR;
                }

                if (_dam_mac_key.Length != 32)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a DAMMAC key. Add --y-dammac-key=XXXX...X to console command.");
                    return ERROR_PARSE_ERROR;
                }
                if (_dam_enc_key.Length != 32)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a Encryption key. Add --z-damenc-key=XXXX...X to console command.");
                    return ERROR_PARSE_ERROR;
                }
                if (InsertCard() == ERROR_NO_ERROR)
                {
                    m_isoWrapping = DueInfoDesfireEv2.DF_ISO_WRAPPING_CARD;
                    m_Desfire = new DueInfoDesfireEv2(m_hCard, m_isoWrapping);

                    m_Desfire.DAMAuthKey = BinConvert.HexToBytes(_dam_auth_key);
                    m_Desfire.DAMENCKey = BinConvert.HexToBytes(_dam_enc_key);
                    m_Desfire.DAMMACKey = BinConvert.HexToBytes(_dam_mac_key);

                    LogManager.DoLogOperation("[INFO] Create DAM ...");
                    if (m_Desfire.AddDelegatedApplicationWithoutWebService())
                    {
                        LogManager.DoLogOperation("[INFO] DAM is created ...");
                    }

                    EjectCard();
                }

            }
            if ((_actions_to_do & ActionToDo.actFreeDam) != 0)
            {
                LogManager.DoLogOperation("[INFO] Free delegated application...");
                if (_reader_id == -1)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a reader. Add --reader=X to console command.");
                    return ERROR_READER_ERROR;
                }
                

                if (_dam_auth_key.Length != 32)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set DAMAuthKey. Add --x-damauth-key=XXXX...X to console command.");
                    return ERROR_PARSE_ERROR;
                }

                if (InsertCard() == ERROR_NO_ERROR)
                {
                    m_isoWrapping = DueInfoDesfireEv2.DF_ISO_WRAPPING_CARD;
                    m_Desfire = new DueInfoDesfireEv2(m_hCard, m_isoWrapping);

                    m_Desfire.AesKeyMaster = BinConvert.HexToBytes(_aes_master_key);
                    m_Desfire.DAMAuthKey = BinConvert.HexToBytes(_dam_auth_key);

                    LogManager.DoLogOperation("[INFO] Delete DAM ...");
                    if (m_Desfire.FormatDelegatedApplication())
                    {
                        LogManager.DoLogOperation("[INFO] DAM is formatted ...");
                    }

                    EjectCard();
                }

            }
            if ((_actions_to_do & ActionToDo.actEraseDam) != 0)
            {
                LogManager.DoLogOperation("[INFO] Erase delegated application...");
                if (_reader_id == -1)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a reader. Add --reader=X to console command.");
                    return ERROR_READER_ERROR;
                }

                if (_aes_master_key.Length != 32)
                {
                    LogManager.DoLogOperation("[WARNING] You have to set a base key. Add --master-key=XXXX...X to console command.");
                    return ERROR_PARSE_ERROR;
                }

                if (InsertCard() == ERROR_NO_ERROR)
                {
                    m_isoWrapping = DueInfoDesfireEv2.DF_ISO_WRAPPING_CARD;
                    m_Desfire = new DueInfoDesfireEv2(m_hCard, m_isoWrapping);

                    m_Desfire.AesKeyMaster = BinConvert.HexToBytes(_aes_master_key);

                    LogManager.DoLogOperation("[INFO] Delete DAM ...");
                    if (m_Desfire.EraseDelegatedApplication())
                    {
                        LogManager.DoLogOperation("[INFO] DAM is deleted ...");
                    }

                    EjectCard();
                }

            }
            
            #endregion
            #region list
            if ((_actions_to_do & ActionToDo.actList) != 0)
            {
                LogManager.DoLogOperation("[INFO]List PCSC readers...");
                for (i = 0; i < m_ReaderList.Count; i++)
                {
                    LogManager.DoLogOperation(string.Format("[INFO]\t{0:X02}\t{1}", i, m_ReaderList[i]));
                }
            }
#endregion
#region pause
            if ((_actions_to_do & ActionToDo.actPause) != 0)
            {
                Console.WriteLine("Hit any key to exit.");
                Console.ReadKey();
            }
#endregion
            return ERROR_NO_ERROR;

        }

        private static bool Transmit(byte[] command, out byte[] response)
        {
            CAPDU capdu = new CAPDU(command);
            RAPDU rapdu = m_hCard.Transmit(capdu);
            response = null;
            if (rapdu == null)
            {
                LogManager.DoLogOperation(string.Format("[ERROR] fails to transmit"));
                return false;
            }
            response = new byte[rapdu.Length];
            Array.Copy(rapdu.Bytes, 0, response, 0, rapdu.Length);
            if (rapdu.SW != 0x9000)
            {
                LogManager.DoLogOperation(string.Format("[ERROR] failed " + SCARD.CardStatusWordsToString(rapdu.SW) + "(" + SCARD.CardStatusWordsToString(rapdu.SW) + ")"));
                return false;
            }


            return true;
        }

        private static bool Iso_Read(ref byte[] escn, ref byte[] sign, ref byte[] cert)
        {
            byte[] SELECT_APP = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x06, 0x14, 0x04, 0xF5, 0x88, 0x40, 0x00 };
            byte[] SELECT_ESCN = new byte[] { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x10, 0x01 };
            byte[] SELECT_SIGN = new byte[] { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x10, 0x02 };
            byte[] SELECT_CERT = new byte[] { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x10, 0x03 };

            byte[] READ_ESCN = new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x00 };
            byte[] READ_SIGN = new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x00 };
            byte[] READ_CERT = new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x00 };


            byte[] response;

            /* DUEINFO, select by its ISO name */
            LogManager.DoLogOperation("[DEBUG] Select DUEINFO Application");
            if (Transmit(SELECT_APP, out response) == false)
            {
                LogManager.DoLogOperation(string.Format("[ERROR] Select DUEINFO Application"));
                return false;
            }

            /* ESCN */
            LogManager.DoLogOperation("[DEBUG] SELECT ESCN FILE 0x1001");
            if (Transmit(SELECT_ESCN, out response) == false)
            {
                LogManager.DoLogOperation(string.Format("[ERROR] Select ESCN File"));
                return false;
            }
            LogManager.DoLogOperation("[DEBUG] READ ESCN FILE 0x1001");
            if (Transmit(READ_ESCN, out response) == false)
            {
                LogManager.DoLogOperation(string.Format("[ERROR] READ ESCN File"));
                return false;
            }
            escn = new byte[response.Length - 2];
            Array.Copy(response, 0, escn, 0, escn.Length);
            LogManager.DoLogOperation(BinConvert.ToHex(escn));

            /* SIGNATURE */
            LogManager.DoLogOperation("[DEBUG] SELECT SIGNATURE FILE 0x1002");
            if (Transmit(SELECT_SIGN, out response) == false)
            {
                LogManager.DoLogOperation(string.Format("[ERROR] Select SIGNATURE File"));
                return false;
            }

            LogManager.DoLogOperation("[DEBUG] READ SIGNATURE FILE 0x1002");
            if (Transmit(READ_ESCN, out response) == false)
            {
                LogManager.DoLogOperation(string.Format("[ERROR] READ ESCN File"));
                return false;
            }
            sign = new byte[response.Length - 2];
            Array.Copy(response, 0, sign, 0, sign.Length);
            LogManager.DoLogOperation(BinConvert.ToHex(sign));

            /* CERTIFICATE */
            LogManager.DoLogOperation("[DEBUG] SELECT CERTIFICATE FILE 0x1003");
            if (Transmit(SELECT_CERT, out response) == false)
            {
                LogManager.DoLogOperation(string.Format("[ERROR] Select CERTIFICATE File"));
                return false;
            }
            LogManager.DoLogOperation("[DEBUG] READ CERTIFICATE FILE 0x1003");
            if (Transmit(READ_CERT, out response) == false)
            {
                LogManager.DoLogOperation(string.Format("[ERROR] READ ESCN File"));
                return false;
            }
            cert = new byte[response.Length - 2];
            Array.Copy(response, 0, cert, 0, cert.Length);
            LogManager.DoLogOperation(BinConvert.ToHex(cert));

            return true;
        }


#region Help

        const string Progname = "DueInfoDesfireEV2";

        public bool InvokeRequired => throw new NotImplementedException();

        static void Banner()
        {

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(" ____          _____     ___     ____          ___ _         _____ _____ ___ ");
            Console.WriteLine("|    \\ _ _ ___|     |___|  _|___|    \\ ___ ___|  _|_|___ ___|   __|  |  |_  |");
            Console.WriteLine("|  |  | | | -_|-   -|   |  _| . |  |  | -_|_ -|  _| |  _| -_|   __|  |  |  _|");
            Console.WriteLine("|____/|___|___|_____|_|_|_| |___|____/|___|___|_| |_|_| |___|_____|\\___/|___|");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine();
        }

        static void Help()
        {
            Banner();
            Console.ForegroundColor = ConsoleColor.DarkGreen;

            Assembly thisAssem = typeof(Program).Assembly;
            AssemblyName thisAssemName = thisAssem.GetName();
            Version ver = thisAssemName.Version;

            Console.WriteLine("This is version {0} of {1}.", ver, thisAssemName.Name);

            Console.WriteLine("Copyright(c) 2000 - 2020 SPRINGCARD SAS");
            Console.WriteLine("FRANCE - www.springcard.com");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("Usage:");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  " + Progname + " <ACTION(S)> [OPTIONS] ");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("Enumerate the PC/SC Reader(s)");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  " + Progname + " list-readers");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("OPTIONS:");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  --master-key=<AES Desfire master key>");
            Console.WriteLine("  --w-divert-key=<AES diversification key for PICCDAMKEYS>");
            Console.WriteLine("  --x-damauth-key=<AES Authentification key for DAM>");
            Console.WriteLine("  --y-damenc-key=<AES Encrypt key for DAM>");
            Console.WriteLine("  --z-dammac-key=<AES Mac key for DAM>");
            Console.WriteLine("  --dueinfo-key=<AES Desfire diversification key>");
            Console.WriteLine("  --escn=<ESCN ID>");
            Console.WriteLine("  --uid=<Card UID>");
            Console.WriteLine("  --reader=<ID of reader to use>");
            Console.WriteLine("  --pause");
            Console.WriteLine("  --verbose");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("ACTIONS:");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  new <create dueinfo application>");
            Console.WriteLine("  disable <disable dueinfoapplication>");
            Console.WriteLine("  read <read dueinfo in clear and create json request>");
            Console.WriteLine("  check <ckeck card integrity>");
            Console.WriteLine("  format <erase PICC and reset PICCDAMKEYS>");
            Console.WriteLine("  loadkey <load PICCDAMKEYS>");
            Console.WriteLine("  newdam <Create DAM sample>");
            Console.WriteLine("  newdamalone <Create DAM sample without web service>");
            Console.WriteLine("  erasedam <Erase DAM sample from DAM List>");
            Console.WriteLine("  freedam <Free memory used by DAM sample>");
            Console.WriteLine("  dammac <Create json request for Web service>");
            Console.WriteLine("  list-readers <list PCSC readers>");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;

        }
#endregion
#region Parse_Arg
        static bool ParseArgs(string[] args)
        {
            int cpt;
            int actionCounter = 0;
            Assembly thisAssem = typeof(Program).Assembly;
            AssemblyName thisAssemName = thisAssem.GetName();

            for (cpt = 0; cpt < args.Length; cpt++)
            {
                if (!args[cpt].StartsWith("-"))
                {
                    /* save action to perform */
                    if (actionCounter > MAX_ACTION_COUNTER)
                    {
                        break;
                    }

                    Actions[actionCounter++] = args[cpt];
                }
            }
            String Action = Actions[0];
            for (actionCounter = 0; actionCounter < MAX_ACTION_COUNTER; actionCounter++)
            {
                Action = Actions[actionCounter];
                if (Action != null)
                {
                    switch (Action.ToLower())
                    {
                        case "new":
                            _actions_to_do |= ActionToDo.actNew;
                            break;
                        case "format":
                            _actions_to_do |= ActionToDo.actFormat;
                            break;
                        case "disable":
                            _actions_to_do |= ActionToDo.actDisable;
                            break;
                        case "read":
                            _actions_to_do |= ActionToDo.actRead;
                            break;
                        case "check":
                            _actions_to_do |= ActionToDo.actCheck;
                            break;
                        case "list-readers":
                            _actions_to_do |= ActionToDo.actList;
                            break;
                        case "loadkey":
                            _actions_to_do |= ActionToDo.actLoadMasterKey;
                            break;
                        case "newdam":
                            _actions_to_do |= ActionToDo.actNewDam;
                            break;
                        case "newdamalone":
                            _actions_to_do |= ActionToDo.actNewDamAlone;
                            break;                            
                        case "erasedam":
                            _actions_to_do |= ActionToDo.actEraseDam;
                            break;
                        case "freedam":
                            _actions_to_do |= ActionToDo.actFreeDam;
                        break;                        
                        case "dammac":
                            _actions_to_do |= ActionToDo.actDammac;
                            break;                           

                        default:
                            break;
                    }
                }
            }

            int c;

            List<LongOpt> options = new List<LongOpt>();

            options.Add(new LongOpt("reader", Argument.Required, null, 'r'));
            options.Add(new LongOpt("master-key", Argument.Required, null, 'm'));
            options.Add(new LongOpt("n-enck", Argument.Required, null, 'n'));
            options.Add(new LongOpt("q-dammac", Argument.Required, null, 'q'));
            options.Add(new LongOpt("w-divert-key", Argument.Required, null, 'w'));
            options.Add(new LongOpt("x-damauth-key", Argument.Required, null, 'x'));
            options.Add(new LongOpt("y-dammac-key", Argument.Required, null, 'y'));
            options.Add(new LongOpt("z-damenc-key", Argument.Required, null, 'z'));            
            options.Add(new LongOpt("dueinfo-key", Argument.Required, null, 'd'));

            options.Add(new LongOpt("escn", Argument.Required, null, 'e'));
            options.Add(new LongOpt("uid", Argument.Required, null, 'u'));

            options.Add(new LongOpt("iso", Argument.No, null, 'i'));
            options.Add(new LongOpt("verbose", Argument.Optional, null, 'v'));
            options.Add(new LongOpt("pause", Argument.No, null, 'p'));
            options.Add(new LongOpt("help", Argument.No, null, 'h'));

            Getopt g = new Getopt(thisAssemName.Name, args, "r:m:n:q:w:x:y:z:d:e:u:ivph", options.ToArray());
            g.Opterr = true;

            while ((c = g.getopt()) != -1)
            {
                string arg = g.Optarg;
                if ((arg != null) && (arg.StartsWith("=")))
                    arg = arg.Substring(1);

                switch (c)
                {
                    case 'v':
                        if (arg != null)
                        {
                            int level;
                            if (int.TryParse(arg, out level))
                                Logger.ConsoleLevel = Logger.IntToLevel(level);

                        }
                        break;
                    case 'p':
                        _actions_to_do |= ActionToDo.actPause;
                        break;

                    case 'h':
                        Help();
                        return true;
                    case 'i':
                        _iso_enable = true;
                        break;
                    case 'r':/* reader */
                        if (int.TryParse(arg, out _reader_id) == false)
                            _reader_id = -1;
                        break;
                    case 'm':/* master ker */
                        if (arg.Length != 32)
                        {
                            Console.WriteLine("Aes key size error {0}.", arg.Length);
                            return false;
                        }
                        _aes_master_key = arg;
                        break;
                    /*case 'n':// new master ker 
                        if (arg.Length != 32)
                        {
                            Console.WriteLine("Aes key size error {0}.", arg.Length);
                            return false;
                        }
                        _aes_new_master_key = arg;
                        break;*/
                    case 'd':/* diversification key */
                        if (arg.Length != 32)
                        {
                            Console.WriteLine("dueinfo-key size error {0}.", arg.Length);
                            return false;
                        }
                        _aes_base_key = arg;
                        break;
                    case 'e': /* escn ID */
                        _escn_id = arg;
                        break;
                    case 'u': /* UID */
                        _card_uid = arg;
                        break;
                    case 'x': /* PICCDAMAuthKey */
                        if (arg.Length != 32)
                        {
                            Console.WriteLine("DAM auth-key size error {0}.", arg.Length);
                            return false;
                        }
                        _dam_auth_key = arg;
                        break;
                    
                    case 'y': /* PICCDAMMACKey */
                        if (arg.Length != 32)
                        {
                            Console.WriteLine("DAM enc-key size error {0}.", arg.Length);
                            return false;
                        }                        
                        _dam_mac_key = arg;
                        break;
                    case 'z': /* PICCDAMENCKey */
                        if (arg.Length != 32)
                        {
                            Console.WriteLine("DAM mac-key size error {0}.", arg.Length);
                            return false;
                        }
                        _dam_enc_key = arg;
                        break;
                    case 'w': /* proprietary root base key used for diversification */
                        if (arg.Length != 32)
                        {
                            Console.WriteLine("Root diversification base key error size error {0}.", arg.Length);
                            return false;
                        }
                        _aes_owner_divert_root_key = arg;
                        break;
                    case 'n': /*  */
                        if (arg.Length == 0)
                        {
                            Console.WriteLine("ENCK error size error {0}.", arg.Length);
                            return false;
                        }
                        _dam_enck = arg;
                        break;
                    case 'q': /*  */
                        if (arg.Length != 16)
                        {
                            Console.WriteLine("DAMMAC error size error {0}.", arg.Length);
                            return false;
                        }
                        _dam_dammac = arg;
                        break;
                    default:
                        goto syntax_error;
                }
            }

            if (_actions_to_do == 0x0000)
            {
                Console.WriteLine("No action requested. Try {0} --help for help.", thisAssemName.Name);
                return false;
            }

            return true;

        syntax_error:
            Console.WriteLine("Syntax error. Try {0} --help for help.", thisAssemName.Name);
            return false;
        }
#endregion
#region card
        static public int InsertCard()
        {
            m_hCard = new SCardChannel(m_ReaderList[_reader_id]);

            if (m_hCard == null)
            {
                return ERROR_INSERT_CARD;
            }

            if (!m_hCard.ConnectExclusive())
            {
                LogManager.DoLogOperation("[ERROR] can't connect to the card");
                //m_hCard.Dispose();
                return ERROR_INSERT_CARD;
            }
            LogManager.DoLogOperation("[INFO] Connected to the card");


            return ERROR_NO_ERROR;

        }
        static public int EjectCard()
        {
            if (m_hCard.Connected == false)
            {
                LogManager.DoLogOperation("[ERROR] can't disconnect from the card");
                return ERROR_INSERT_CARD;
            }
            m_hCard.DisconnectReset();
            //m_hCard.Dispose();

            LogManager.DoLogOperation("[INFO] Disconnected from the card");

            return ERROR_NO_ERROR;
        }

        public IAsyncResult BeginInvoke(Delegate method, object[] args)
        {
            throw new NotImplementedException();
        }

        public object EndInvoke(IAsyncResult result)
        {
            throw new NotImplementedException();
        }

        public object Invoke(Delegate method, object[] args)
        {
            throw new NotImplementedException();
        }
#endregion
        
    }
}
