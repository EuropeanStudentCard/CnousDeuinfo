using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DamWebService
{
    public static class Converters
    {

        public static string ByteArrayToString(byte[] bytes)
        {
            return Encoding.UTF8.GetString(bytes);
        }

        public static string ByteArrayToSimpleHexString(byte[] bytes)
        {
            var sb = new List<string>();

            foreach (var b in bytes)
            {
                sb.Add(b.ToString("X2"));
            }

            return string.Join(":", sb.ToArray());
        }

        public static string[] ByteArrayToStringArray(byte[] ba)
        {
            if (ba == null || ba.Length == 0)
            {
                return null;
            }
            else
            {
                var res = new string[ba.Length];

                int i = 0;
                foreach (var b in ba)
                {
                    res[i++] = $"0x{b:x2}";
                }
                return res;
            }
        }

        public static byte[] StringToByteArray(string[] hexs)
        {
            if (hexs == null /*|| hexs.Length != 16*/)
            {
                return null;
            }
            else
            {
                byte[] bytes = new byte[hexs.Length];

                int i = 0;
                foreach (var hex in hexs)
                {
                    var value = string.Empty;
                    if (hex.ToLower().StartsWith("0x"))
                    {
                        value = hex.Substring(2);
                        bytes[i++] = Convert.ToByte(value, 16);
                    }
                }
                return bytes;
            }
        }

        public static string ByteToStringArray(byte ba)
        {
            var res = $"0x{ba:x2}";
            return res;
        }
        public static byte StringToByte(string hexs)
        {
            if (hexs == null )
            {
                return 0x00;
            }
            else
            {
                byte bytes = 0x00;
                var value = string.Empty;

                if (hexs.ToLower().StartsWith("0x"))
                {
                    value = hexs.Substring(2);
                    bytes = Convert.ToByte(value, 16);
                }

                return bytes;
            }
        }    

    }
}
