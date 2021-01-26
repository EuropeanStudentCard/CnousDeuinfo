using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DueInfo
{
    class Console_OpenSsl //: ISynchronizeInvoke
    {
        private Process myProcess;
        private ProcessStartInfo myProcessStartInfo;

        public enum ActionOpenSsl
        {
            actSign = 0x0001,
            actSignVerify = 0x0002,
            actDerToPem = 0x0004,
            actExtractPubKey = 0x0008,
            actVersion = 0x0010
        };
        const string app_name = "openssl.exe";

        const string convert_der_to_pem = "x509 -inform der -in {0} -out {1}";
        const string extract_pub_ker_from_pem = "x509 -pubkey -noout -in {0} -out {1}";
        const string create_sign_args = "dgst -sha256 -passin pass:{0} -sign {1} -out {2} {3}";
        const string verif_sign_args = "dgst -sha256 -passin pass:{0} -verify {1} -signature {2} {3}";

        public event EventHandler procExit;
        public event DataReceivedEventHandler procErrorDataReceived;
        public event DataReceivedEventHandler procOutputDataReceived;

        #region _console
        public void InitializeMyProcess(ISynchronizeInvoke caller = null)
        {
            this.myProcess = new Process();
            this.myProcess.SynchronizingObject = caller;
            this.myProcess.EnableRaisingEvents = true;
            this.myProcess.Exited += new System.EventHandler(procExit);
            this.myProcess.ErrorDataReceived += new System.Diagnostics.DataReceivedEventHandler(procErrorDataReceived);
            this.myProcess.OutputDataReceived += new System.Diagnostics.DataReceivedEventHandler(procOutputDataReceived);
        }
        public string CreateArguments(ActionOpenSsl action, List<string> var)
        {
            string args = "";
            if( action == ActionOpenSsl.actSign)
            {
                if (var.Count >= 4)
                    args = string.Format(create_sign_args, var[0], var[1], var[2], var[3]);
                
            }
            else if (action == ActionOpenSsl.actSignVerify)
            {
                if (var.Count >= 4)
                    args = string.Format(verif_sign_args, var[0], var[1], var[2], var[3]);
            }
            else if (action == ActionOpenSsl.actDerToPem)
            {
                if (var.Count >= 2)
                    args = string.Format(convert_der_to_pem, var[0], var[1]);
            }
            else if (action == ActionOpenSsl.actExtractPubKey)
            {
                if (var.Count >= 2)
                    //args = string.Format(extract_pub_ker_from_pem, var[0]);
                    args = string.Format(extract_pub_ker_from_pem, var[0], var[1]);
            }
            else if (action == ActionOpenSsl.actVersion)
            {
                args = string.Format("version");
            }
            

            if (args.Length == 0)
                return null;

            return args;
        }
        public void InitializeMyProcessStartInfo(string args)
        {
            myProcessStartInfo = new ProcessStartInfo(app_name, args);
            this.myProcessStartInfo.RedirectStandardError = true;
            this.myProcessStartInfo.RedirectStandardInput = true;
            this.myProcessStartInfo.RedirectStandardOutput = true;

            this.myProcessStartInfo.UseShellExecute = false;
            this.myProcessStartInfo.CreateNoWindow = true;
        }
        public void StartProcess()
        {
            this.myProcess.StartInfo = this.myProcessStartInfo;
            this.myProcess.Start();
            this.myProcess.BeginErrorReadLine();
            this.myProcess.BeginOutputReadLine();
        }
        
#endregion //_console
    }
}
