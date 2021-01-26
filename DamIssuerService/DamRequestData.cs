using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DamWebService
{
    public class DamRequestData : JsonableObject
    {
        /* identification_number */
        public string ID;
        /* Pic */
        public string PIC;
        /* Aid */
        public string AID;
        /* quotaLimit */
        public string QUOTA;
        /* KeySettings1 */
        public string KS1;
        /* KeySettings2 */
        public string KS2;
        /* Additional optional key settings */
        public string KS3;
        /* Key Set Version of the Active Key Set */
        public string AKSVERSION;
        /* Number of Key Sets 2 to 16 */
        public string NOKEYSET;
        /*  Max. Key Size 0x10 or 0x18 */
        public string MAXKEYSIZE;
        /* Application Key Set Setting, */
        public string ROLLKEY;
        /* ISO/IEC 7816-4 File Identifier */
        public string ISODFID;
        /* ISO/IEC 7816-4 DF Name for this application */
        public string ISODFNAME;
        
        /* DAM Default Key for creation */
        public string DAMDEFAULTKEY;

    }
}
