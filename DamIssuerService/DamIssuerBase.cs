using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DamWebService
{
    public interface DamIssuerBase
    {
        void StopRequest();
        void NotifyUser(int timeout, string title, string text, string icon);
        string GetMode();
        string GetPlatform();
    }
}
