using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SpringCard.LibCs;
using SpringCard.LibCs.Windows;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace DamWebService
{
    class DamWebService : JsonableObject
    {
        public string Name = "DAM Issuer Service";
        public string Version;
        public string API = "1.0";
        public const byte DF_CREATE_DELEGATED_APPLICATION = 0xC9;

        public DamWebService()
        {
            LogManager.DoLogOperation("Creating the DAM Issuer Service entity");
            FileVersionInfo info = FileVersionInfo.GetVersionInfo(Assembly.GetAssembly(typeof(DamWebService)).Location);
            this.Version = info.ProductVersion;
        }

        #region DamRequest

        private class DamCommand
        {
            public string Request = null;
        }

        public string DamRequestCreate(string jsonFile)
        {
            LogManager.DoLogOperation("[DAM Server] Receive Request to create DAM");

            DamRestCommand.JsonDamCreate test = DamRestCommand.LoadJson_DamCreate(jsonFile);
            /* format json response */
            JObject result = new JObject();
            JProperty a;
            JProperty b;
            JProperty c;
            /*Calculate EncK*/
            byte[] EncK = DamCrypto.EncK(test.damauthkey, test.damdefaultkey, test.damdefaultkeyversion);

            /* secret dammac key */
            byte[] DAMMACKey = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            uint iAid = 0x000000;
            if(test.aid.Length != 3)
            {
                a = new JProperty("Enk", Converters.ByteArrayToSimpleHexString(EncK));
                result.Add(a);
                b = new JProperty("DAMMAC", Converters.ByteArrayToSimpleHexString(EncK));
                result.Add(b);
                c = new JProperty("status", "aid error");
                result.Add(c);

                return JsonConvert.SerializeObject(result, Formatting.Indented);
            }
            
            iAid = test.aid[2];
            iAid += (uint) (test.aid[1] << 8);
            iAid += (uint)(test.aid[0] << 16);
            
            /* Calculate DAMMAC */
            byte[] dammac = DamCrypto.DAMMAC(
                DAMMACKey,
                DF_CREATE_DELEGATED_APPLICATION,
                iAid, test.damslotno, test.damslotversion, test.quotalimit, test.key_setting1, test.key_setting2,
                test.key_setting3, test.aksversion, test.nokeyset, test.maxkeysize, test.rollkey,
                test.iso_df_id, test.iso_df_name,
                EncK);

            c = new JProperty("Result", "ok");
            result.Add(c);
            /* le proprietaire connait les valeurs en fonction de sa base de données */
            /* les valeurs correspondent au DAMMAC crée */
            c = new JProperty("damslotno", "0");
            result.Add(c);
            c = new JProperty("damslotversion", "FF");
            result.Add(c);
            c = new JProperty("quotalimit", "10");
            result.Add(c);

            a = new JProperty("Enck", Converters.ByteArrayToSimpleHexString(EncK));
            result.Add(a);
            b = new JProperty("DAMMAC", Converters.ByteArrayToSimpleHexString(dammac));
            result.Add(b);            

            return JsonConvert.SerializeObject(result, Formatting.Indented);
        }

        public string DamRequestAuthKey(string jsonFile)
        {
            LogManager.DoLogOperation("[DAM Server] Receive Request to get PICCDAMAuthKey");
            
            DamRestCommand.JsonDamAuthKey test = DamRestCommand.LoadJson_DamAuthKey(jsonFile);

            LogManager.DoLogOperation("[SERVER] Retrieve Diversified key from " + BinConvert.ToHex(test.uid));

            byte[] AesKeyDiversified = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

            /* le propriétaire connait sa clef racine utilisée pour sa diversification de clef */
            byte[] AesKeyRootDiversified = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };

            DueInfo.Diversification.Diversification_AES128(AesKeyRootDiversified, test.uid, test.uid.Length, ref AesKeyDiversified);

            LogManager.DoLogOperation("[SERVER] Diversified key is " + BinConvert.ToHex(AesKeyDiversified));

            /* format json response */
            JObject result = new JObject();

            JProperty d = new JProperty("Result", "ok");
            result.Add(d);

            JProperty a = new JProperty("uid", Converters.ByteArrayToSimpleHexString(test.uid));
            result.Add(a);
            JProperty b = new JProperty("damauthkey", Converters.ByteArrayToSimpleHexString(AesKeyDiversified));
            result.Add(b);
            /* le propriétaire connait le numéro de version de sa clef */
            /*string version = "00";
            JProperty c = new JProperty("damauthkeyversion", version);
            result.Add(c);            */

            return JsonConvert.SerializeObject(result, Formatting.Indented);
        }
        
        #endregion
    }
}
