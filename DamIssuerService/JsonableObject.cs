using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DamWebService
{
    public class JsonableObject
    {
        public override string ToString()
        {
            return JsonConvert.SerializeObject(this, Formatting.None);
        }

        public JObject ToJObject()
        {
            return (JObject)JsonConvert.DeserializeObject(this.ToString());
        }
    }
}
