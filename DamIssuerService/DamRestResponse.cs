using Grapevine.Server;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace DamWebService
{
    public sealed partial class DamRestController : RESTResource
    {
        public enum HttpCode
        {
            OK = 200,
            Bad_Request = 400,
            Unauthorized = 401,
            Forbidden = 403,
            Not_Found = 404,
            Method_Not_Allowed = 405,
            Not_Acceptable = 406,
            Conflict = 409,
            Gone = 410,
            Unprocessable_Entity = 422,
            Device_error = 499,
            Internal_Server_Error = 500,
            Service_Unavailable = 503
        }

        private void SendResponse(HttpListenerContext context, string payload)
        {
            context.Response.AddHeader("Content-Type", "application/json");
            context.Response.AddHeader("Access-Control-Allow-Origin", "*");
            SendTextResponse(context, payload);
        }

        private void SendResponseOptions(HttpListenerContext context)
        {
            context.Response.StatusCode = 200;
            context.Response.StatusDescription = "OK";
            context.Response.AddHeader("Content-Type", "application/json");
            context.Response.AddHeader("Access-Control-Allow-Origin", "*");
            context.Response.AddHeader("Access-Control-Allow-Methods", "OPTIONS, GET, POST, PUT, DELETE");
            context.Response.AddHeader("Access-Control-Allow-Headers", "Content-Type");
            SendTextResponse(context, null);
            //SendEmptyResponse(context);
        }

        private void SendResponse(HttpListenerContext context, JsonableObject payload)
        {
            SendResponse(context, payload.ToString());
        }

        private void SendResponseSuccess(HttpListenerContext context)
        {
            JObject outData = new JObject(
                    new JProperty("Result", "success")
                );
            SendResponse(context, JsonConvert.SerializeObject(outData, Formatting.Indented));
        }

        private void SendResponseError(HttpListenerContext context, HttpCode code)
        {
            JObject outData = new JObject(
                    new JProperty("Result", "error")
                );
            context.Response.StatusCode = (int)code;
            context.Response.StatusDescription = code.ToString().Replace('_', ' ');
            SendResponse(context, JsonConvert.SerializeObject(outData, Formatting.Indented));
        }

        private void SendResponseSuccessOrError(HttpListenerContext context, bool success)
        {
            if (success)
                SendResponseSuccess(context);
            else
                SendResponseError(context, HttpCode.Device_error);
        }

        private void SendResponse(HttpListenerContext context, DamRestResponse response)
        {
            HttpCode code = response.Code;
            context.Response.StatusCode = (int)code;
            context.Response.StatusDescription = code.ToString().Replace('_', ' ');
            SendResponse(context, response.Content);
        }

        public class DamRestResponse : JsonableObject
        {
            private HttpCode code;
            private string message;

            public HttpCode Code
            {
                get
                {
                    return code;
                }
            }

            public string Content
            {
                get
                {
                    JObject result;

                    if (code == HttpCode.OK)
                    {
                        result = new JObject(
                            new JProperty("Result", "success")
                        );
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(message))
                        {
                            result = new JObject(
                                new JProperty("Result", "error"),
                                new JProperty("Message", message)
                            );
                        }
                        else
                        {
                            result = new JObject(
                                new JProperty("Result", "error")
                            );
                        }
                    }

                    return JsonConvert.SerializeObject(result, Formatting.Indented);
                }
            }

            public static DamRestResponse Success()
            {
                DamRestResponse result = new DamRestResponse();
                result.code = HttpCode.OK;
                return result;
            }

            public static DamRestResponse Error(HttpCode code, string message)
            {

                LogManager.DoLogOperation(string.Format("Error response: {0}/{1}", (int)code, message));
                DamRestResponse result = new DamRestResponse();
                result.code = code;
                result.message = message;
                return result;
            }

            public static DamRestResponse Error(string message = "Invalid data")
            {
                return Error(HttpCode.Unprocessable_Entity, message);
            }
        }
    }
}
