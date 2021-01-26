using Newtonsoft.Json;
using SpringCard.LibCs;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace DamWebService
{
    class DamRestCommand
    {
        public static string RequestToString(HttpListenerRequest request)
        {
            string result;
            using (Stream stream = request.InputStream)
            {
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
                {
                    result = reader.ReadToEnd();
                }
            }
            return result;
        }

        public class FileJSON
        {
            [JsonProperty("file")]
            public string file { get; set; }
        }
        

        public static string GetFileFromRequest(HttpListenerRequest request, out DamRestController.DamRestResponse errorResponse)
        {
            FileJSON command;
            try
            {
                command = JsonConvert.DeserializeObject<FileJSON>(RequestToString(request));
                if( command == null)
                {
                    errorResponse = DamRestController.DamRestResponse.Error();
                    return null;
                }
                Console.WriteLine($"Received request for {request.Url}");
                Console.WriteLine(command);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                errorResponse = DamRestController.DamRestResponse.Error();
                return null;
            }

            /*if (string.IsNullOrEmpty(command.uid))
            {
                errorResponse = DamRestController.DamRestResponse.Error("File missing");
                return null;
            }*/
            string localFileName = null;

            if (command.file.Contains("://"))
            {
                if (command.file.StartsWith("file://"))
                {
                    /* For sure this is a local file */
                    localFileName = command.file.Substring(7);
                }
                else if (command.file.StartsWith("http://") || command.file.StartsWith("https://"))
                {
                    localFileName = Path.GetTempFileName();
                    RestClient restClient = new RestClient();
                    if (!restClient.DownloadBinaryFile(command.file, localFileName))
                    {
                        errorResponse = DamRestController.DamRestResponse.Error("Download failed");
                        return null;
                    }
                }
                else
                {
                    /* Unsupported URL scheme */
                    errorResponse = DamRestController.DamRestResponse.Error("Scheme not supported");
                    return null;
                }
            }
            else
            {
                /* Maybe it is a local file? */
                localFileName = command.file;
            }

            /* Now the file must exist... */
            if (localFileName != null)
            {
                if (!File.Exists(localFileName))
                {
                    errorResponse = DamRestController.DamRestResponse.Error("File not found");
                    return null;
                }
                if (!FileUtils.IsReadable(localFileName))
                {
                    errorResponse = DamRestController.DamRestResponse.Error("Access denied");
                    return null;
                }
            }

            errorResponse = null;
            return localFileName;
        }

        /// <summary>
        /// JSON for request PICCDAMAuthKey
        /// </summary>
        public class JsonDamAuthKey
        {
            [JsonProperty("uid")]
            private string[] uidAsHex { get; set; }

            [JsonIgnore]
            public byte[] uid { get => Converters.StringToByteArray(uidAsHex); set => uidAsHex = Converters.ByteArrayToStringArray(value); }

        }
        public static JsonDamAuthKey LoadJson_DamAuthKey(string filename)
        {
            using (StreamReader r = new StreamReader(filename))
            {
                string json = r.ReadToEnd();
                JsonDamAuthKey item = JsonConvert.DeserializeObject<JsonDamAuthKey>(json);
                return item;
            }
        }
        /// <summary>
        /// JSON to create DAM
        /// </summary>
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
        public static JsonDamCreate LoadJson_DamCreate(string filename)
        {
            using (StreamReader r = new StreamReader(filename))
            {
                string json = r.ReadToEnd();
                JsonDamCreate item = JsonConvert.DeserializeObject<JsonDamCreate>(json);
                return item;
            }
        }
    }
}
