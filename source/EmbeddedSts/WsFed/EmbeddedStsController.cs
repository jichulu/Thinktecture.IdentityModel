﻿/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see LICENSE
 */

using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Services;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Web.Mvc;
using System.Xml.Linq;
using Thinktecture.IdentityModel.EmbeddedSts.Assets;

namespace Thinktecture.IdentityModel.EmbeddedSts.WsFed
{
    [AllowAnonymous]
    public class EmbeddedStsController : Controller
    {
        private ContentResult Html(string html)
        {
            return Content(html, "text/html");
        }

        public ActionResult Index()
        {
            var message = WSFederationMessage.CreateFromUri(Request.Url);
            var signInMsg = message as SignInRequestMessage;
            if (signInMsg != null)
            {
                var user = GetUser();
                if (user != null)
                {
                    return ProcessSignIn(signInMsg, user);
                }
                else
                {
                    return ShowUserList();
                }
            }

            var signOutMsg = message as SignOutRequestMessage;
            if (signOutMsg != null)
            {
                return ProcessSignOut(signOutMsg);
            }

            return new EmptyResult();
        }

        private ActionResult ShowUserList()
        {
            var html = AssetManager.LoadString(EmbeddedStsConstants.SignInFile);

            var users = UserManager.GetAllUserNames();
            var options = "";
            foreach (var user in users)
            {
                options += String.Format("<option value='{0}'>{0}</option>", user);
            }
            html = html.Replace("{options}", options);

            var url = Request.Url.PathAndQuery;
            html = html.Replace("{signInUrl}", url);

            return Html(html);
        }

        private ClaimsPrincipal GetUser()
        {
            var username = Request.Form["username"];
            if (String.IsNullOrWhiteSpace(username)) return null;

            var claims = UserManager.GetClaimsForUser(username);
            if (claims == null || !claims.Any()) return null;
            //Basic authentication, NTLM, Kerberos, and Passport
            var id = new ClaimsIdentity(claims, "Basic authentication");

            return new ClaimsPrincipal(id);
        }

        private ActionResult ProcessSignIn(SignInRequestMessage signInMsg, ClaimsPrincipal user)
        {
            var config = new EmbeddedTokenServiceConfiguration();
            var sts = config.CreateSecurityTokenService();

            var appPath = Request.ApplicationPath;
            if (!appPath.EndsWith("/")) appPath += "/";

            // when the reply querystringparameter has been specified, don't overrule it. 
            if (string.IsNullOrEmpty(signInMsg.Reply))
                signInMsg.Reply = new Uri(Request.Url, appPath).AbsoluteUri;
            if (!string.IsNullOrEmpty(signInMsg.Realm))
            {
                signInMsg.Reply = signInMsg.Realm;
            }
            if (!string.IsNullOrEmpty(signInMsg.Reply))
            {
                var ub = new UriBuilder(signInMsg.Reply);
                if (ub.Scheme != Uri.UriSchemeHttps)
                {
                    ub.Scheme = Uri.UriSchemeHttps;
                    ub.Port = 443;
                }
                signInMsg.Reply = ub.ToString();
            }


            FederatedPassiveSecurityTokenServiceOperations.ProcessRequest(System.Web.HttpContext.Current.Request, user, sts, System.Web.HttpContext.Current.Response, new WSFederationSerializer());
            //var response = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(signInMsg, user, sts);

            //var body = response.WriteFormPost();
            //return Html(body);

            return new HttpStatusCodeResult(System.Net.HttpStatusCode.OK);
        }

        private ActionResult ProcessSignOut(SignOutRequestMessage signOutMsg)
        {
            var appPath = Request.ApplicationPath;
            if (!appPath.EndsWith("/")) appPath += "/";

            var rpUrl = new Uri(Request.Url, appPath);
            var signOutCleanupMsg = new SignOutCleanupRequestMessage(rpUrl);
            var signOutUrl = signOutCleanupMsg.WriteQueryString();

            var html = AssetManager.LoadString(EmbeddedStsConstants.SignOutFile);
            html = html.Replace("{redirectUrl}", signOutMsg.Reply);
            html = html.Replace("{signOutUrl}", signOutUrl);

            return Html(html);
        }

        public ActionResult WsFederationMetadata()
        {
            var config = new EmbeddedTokenServiceConfiguration();
            var uri = new Uri(Request.Url.AbsoluteUri).GetLeftPart(UriPartial.Authority);
            var claims = UserManager.GetAllUniqueClaimTypes();
            var metadataXml = config.GetFederationMetadata(uri, claims).ToString(SaveOptions.DisableFormatting);
            return Content(metadataXml, "application/xml");
        }
    }
}
