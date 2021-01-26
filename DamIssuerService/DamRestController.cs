using Grapevine.Server;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using Grapevine;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using Grapevine.Client;
using SpringCard.LibCs;

namespace DamWebService
{
    public sealed partial class DamRestController : RESTResource
    {
        #region Constructor
        public DamRestController()
        {
            LogManager.DoLogOperation("DamRestController constructs object");
        }
        #endregion

        #region Utilities
        private string StripSlashes(string s)
        {
            return s.Replace("/", "");
        }

        #endregion

        #region /service routes

        [RESTRoute(Method = HttpMethod.GET, PathInfo = "/dam_version")]
        public void GetService(HttpListenerContext context)
        {
            LogManager.DoLogOperation("GET /dam_version");
            SendResponse(context, DamIssuer.service.ToString());
        }

        [RESTRoute(Method = HttpMethod.POST, PathInfo = "/dam_request_create")]
        public void PostDamRequestCreate(HttpListenerContext context)
        {
            LogManager.DoLogOperation("POST /dam_request_create");
            DamRestResponse errorResponse;
            string jsonFile = DamRestCommand.GetFileFromRequest(context.Request, out errorResponse);
            if (jsonFile == null)
            {
                errorResponse = DamRestController.DamRestResponse.Error("File not found");
                SendResponse(context, errorResponse);
                return;
            }
            string response = DamIssuer.service.DamRequestCreate(jsonFile);
            if (response == null)
                SendResponseError(context, HttpCode.Device_error);
            else
                SendResponse(context, response);
        }

        [RESTRoute(Method = HttpMethod.POST, PathInfo = "/dam_request_auth_key")]
        public void PostDamRequestAuthKey(HttpListenerContext context)
        {
            LogManager.DoLogOperation("POST /dam_request_auth_key");
            DamRestResponse errorResponse;
            string jsonFile = DamRestCommand.GetFileFromRequest(context.Request, out errorResponse);
            if (jsonFile == null)
            {
                errorResponse = DamRestController.DamRestResponse.Error("File not found");
                SendResponse(context, errorResponse);
                return;
            }
            string response = DamIssuer.service.DamRequestAuthKey(jsonFile);
            if (response == null)
                SendResponseError(context, HttpCode.Device_error);
            else
                SendResponse(context, response);
        }

        #endregion

    }
}
