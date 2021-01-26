using CommandLine;
using CommandLine.Text;
using Grapevine;
using Grapevine.Client;
using Grapevine.Server;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static DamWebService.DamRestCommand;

namespace DamWebService
{

    class Options
    {
        [Option("server", DefaultValue = false, Required = false, HelpText = "Run as REST server.")]
        public bool RunAsServer { get; set; }

        [Option("host", DefaultValue = "localhost", Required = false, HelpText = "Set host IP.")]
        public string Host { get; set; }

        [Option("port", DefaultValue = "1234", Required = false, HelpText = "Set host port.")]
        public string Port { get; set; }

        [Option("url", DefaultValue = "/", Required = false,
            HelpText = @"URL after [host:port]. Should start with '/'.")]
        public string Url { get; set; }

        [Option("method", DefaultValue = "GET", Required = false, HelpText = "GET, POST.")]
        public string Method { get; set; }

        [Option("timeout", DefaultValue = -1, Required = false,
            HelpText = "Request timeout in milliseconds. When value is -1, client will use " +
            "the default timeout set in GrapeVine (1.21 seconds).")]
        public int Timeout { get; set; }

        [Option("json", DefaultValue = "", Required = false,
            HelpText = @"Name of json file to open.")]
        public string Json { get; set; }


        [HelpOption]
        public string GetHelp()
        {
            return HelpText.AutoBuild(this, (HelpText current) =>
                HelpText.DefaultParsingErrorsHandler(this, current));
        }
    }
    /*public class JsonDamAuthKey
    {
        public byte[] uid;
        public string status;
    }*/
    public class JsonDamCreate
    {        
        /* used for EncK*/
        public byte[] DAMENCKey;
        public byte[] DamDefaultKey;
        public byte DamDefaultKeyVersion;

        /*used for DAMMAC*/
        public UInt16 access_rights;
        public UInt32 aid;
        public UInt16 damSlotNo;
        public byte damSlotVersion;
        public UInt16 quotaLimit = 0x0010;
        public byte KS1;
        public byte KS2;
        public byte KS3;
        public byte aksVersion;
        public byte noKeySet;
        public byte maxKeySize;
        public byte RollKey;
        public ushort iso_df_id;
        public byte[] iso_df_name;

        public string status;
    }

    class Program //: DamIssuerBase
    {
        private const string req_auth_key = "{\"uid\":\"{0}\",\"status\":\"{1}\"}";

        static void Main(string[] args)
        {
            var exitEvent = new ManualResetEvent(false);
            var options = new Options();

            if (CommandLine.Parser.Default.ParseArgumentsStrict(args, options, () => { Environment.Exit(-2); }))
            {
                if (options.RunAsServer)
                {
                    //
                    // As server
                    //
                    Console.CancelKeyPress += (sender, eventArgs) => {
                        eventArgs.Cancel = true;
                        exitEvent.Set();
                    };

                    Console.WriteLine("Run server on " + options.Host + ":" + options.Port);
                    Console.WriteLine("Press CTRL+C to terminate server.\n");
                    Console.WriteLine("Host: {0}:{1}", options.Host, options.Port);

                    try
                    {
                        LogManager.InstantiateLogManager();                                               
                        
                        DamIssuer.Init();

                        var server = new RESTServer();
                        server.Host = options.Host;
                        server.Port = options.Port;
                        server.Start();

                        exitEvent.WaitOne();
                        server.Stop();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message + "\n" + e.StackTrace);
                    }
                }
                else
                {
                    Dictionary<string, HttpMethod> method = new Dictionary<string, HttpMethod>()
                    {
                        { "GET", HttpMethod.GET },
                        { "POST", HttpMethod.POST }
                    };

                    //
                    // As client
                    //
                    try
                    {
                        LogManager.InstantiateLogManager();

                        RESTClient client = new RESTClient("http://" + options.Host + ":" + options.Port);

                        RESTRequest request = new RESTRequest(options.Url);
                        request.Method = method[options.Method];
                        request.ContentType = ContentType.JSON;
                        request.Payload = string.Format("{{\"file\":\"{0}\"}}", options.Json );
                        Console.WriteLine("Payload: " + request.Payload);

                        var response = client.Execute(request);
                        Console.WriteLine("Response: " + response.Content);

                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message + "\n" + e.StackTrace);
                    }

                }
            }
        }

    }
}
