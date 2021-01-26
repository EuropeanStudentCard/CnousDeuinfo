using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DamWebService
{
    static class DamIssuer
    {
        public static DamWebService service;

        public static void Init(/*DamIssuerBase damObject*/)
        {
            LogManager.DoLogOperation("Creating the DAM Issuer");
            service = new DamWebService();
        }

        public static void Cleanup()
        {
        }
    }
}
