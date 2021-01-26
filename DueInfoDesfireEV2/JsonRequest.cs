using DamWebService;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DueInfoDesfireEV2
{
    class JsonRequest
    {
        public class JsonDamAuthKey
        {
            [JsonProperty("uid")]
            private string[] uidAsHex { get; set; }

            [JsonIgnore]
            public byte[] uid { get => Converters.StringToByteArray(uidAsHex); set => uidAsHex = Converters.ByteArrayToStringArray(value); }

        }
        public static void create_auth_json(string filename, byte[] uid)
        {
            JsonDamAuthKey data = new JsonDamAuthKey();

            data.uid = uid;

            using (StreamWriter r = new StreamWriter(filename))
            {
                string jsonData = JsonConvert.SerializeObject(data);
                r.Write(jsonData);
                return;
            }
        }
        public class JsonDamCreate
        {
            [JsonProperty("damauthkey")]
            private string[] damauthkeyAsHex { get; set; }

            [JsonIgnore]
            public byte[] damauthkey { get => Converters.StringToByteArray(damauthkeyAsHex); set => damauthkeyAsHex = Converters.ByteArrayToStringArray(value); }

            /*[JsonProperty("damauthkeyversion")]
            private string damauthkeyversionAsHex { get; set; }
            [JsonIgnore]
            public byte damauthkeyversion { get => Converters.StringToByte(damauthkeyversionAsHex); set => damauthkeyversionAsHex = Converters.ByteToStringArray(value); }
            */

            [JsonProperty("damdefaultkey")]
            private string[] damdefaultkeyAsHex { get; set; }

            [JsonIgnore]
            public byte[] damdefaultkey { get => Converters.StringToByteArray(damdefaultkeyAsHex); set => damdefaultkeyAsHex = Converters.ByteArrayToStringArray(value); }

            [JsonProperty("damdefaultkeyversion")]
            private string damdefaultkeyversionAsHex { get; set; }
            [JsonIgnore]
            public byte damdefaultkeyversion { get => Converters.StringToByte(damdefaultkeyversionAsHex); set => damdefaultkeyversionAsHex = Converters.ByteToStringArray(value); }


            [JsonProperty("aid")]
            private string[] aidAsHex { get; set; }

            [JsonIgnore]
            public byte[] aid { get => Converters.StringToByteArray(aidAsHex); set => aidAsHex = Converters.ByteArrayToStringArray(value); }

            [JsonProperty("damslotno")]
            public ushort damslotno { get; set; }

            [JsonProperty("damslotversion")]
            private string damslotversionAsHex { get; set; }
            [JsonIgnore]
            public byte damslotversion { get => Converters.StringToByte(damslotversionAsHex); set => damslotversionAsHex = Converters.ByteToStringArray(value); }

            [JsonProperty("quotalimit")]
            public ushort quotalimit { get; set; }

            [JsonProperty("key_setting1")]
            private string key_setting1AsHex { get; set; }
            [JsonIgnore]
            public byte key_setting1 { get => Converters.StringToByte(key_setting1AsHex); set => key_setting1AsHex = Converters.ByteToStringArray(value); }

            [JsonProperty("key_setting2")]
            private string key_setting2AsHex { get; set; }
            [JsonIgnore]
            public byte key_setting2 { get => Converters.StringToByte(key_setting2AsHex); set => key_setting2AsHex = Converters.ByteToStringArray(value); }

            [JsonProperty("key_setting3")]
            private string key_setting3AsHex { get; set; }
            [JsonIgnore]
            public byte key_setting3 { get => Converters.StringToByte(key_setting3AsHex); set => key_setting3AsHex = Converters.ByteToStringArray(value); }

            [JsonProperty("aksversion")]
            private string aksversionAsHex { get; set; }
            [JsonIgnore]
            public byte aksversion { get => Converters.StringToByte(aksversionAsHex); set => aksversionAsHex = Converters.ByteToStringArray(value); }

            [JsonProperty("nokeyset")]
            private string nokeysetAsHex { get; set; }
            [JsonIgnore]
            public byte nokeyset { get => Converters.StringToByte(nokeysetAsHex); set => nokeysetAsHex = Converters.ByteToStringArray(value); }

            [JsonProperty("maxkeysize")]
            private string maxkeysizeAsHex { get; set; }
            [JsonIgnore]
            public byte maxkeysize { get => Converters.StringToByte(maxkeysizeAsHex); set => maxkeysizeAsHex = Converters.ByteToStringArray(value); }

            [JsonProperty("rollkey")]
            private string rollkeyAsHex { get; set; }
            [JsonIgnore]
            public byte rollkey { get => Converters.StringToByte(rollkeyAsHex); set => rollkeyAsHex = Converters.ByteToStringArray(value); }

            [JsonProperty("iso_df_id")]
            public ushort iso_df_id { get; set; }

            [JsonProperty("iso_df_name")]
            public string[] iso_df_nameAsHex { get; set; }

            [JsonIgnore]
            public byte[] iso_df_name { get => Converters.StringToByteArray(iso_df_nameAsHex); set => iso_df_nameAsHex = Converters.ByteArrayToStringArray(value); }

        }
        public static void create_dammac_json(string filename, byte[] damkey)
        {
            JsonDamCreate data = new JsonDamCreate();

            data.aid = new byte[3] { 0xF5, 0x85, 0x40 };
            data.damslotno = 0x0000;
            data.damslotversion = 0xFF;
            data.quotalimit = 16;

            data.key_setting1 = 0x0B;
            data.key_setting2 = 0xA3;
            data.key_setting3 = 0x00;
            data.aksversion = 0x00;
            data.nokeyset = 0x00;
            data.maxkeysize = 0x00;
            data.rollkey = 0x00;

            data.iso_df_id = 4096;
            data.iso_df_name = new byte[] { 0xA0, 0x00, 0x00, 0x06, 0x14, 0x04, 0xF5, 0x85, 0x40 };

            data.damauthkey = damkey;
            data.damdefaultkey = new byte[16];
            data.damdefaultkeyversion = 0x00;

            using (StreamWriter r = new StreamWriter(filename))
            {
                string jsonData = JsonConvert.SerializeObject(data);
                r.Write(jsonData);
                return;
            }
        }
    }
}
