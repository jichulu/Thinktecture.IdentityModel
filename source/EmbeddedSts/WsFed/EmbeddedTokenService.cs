/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see LICENSE
 */

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Metadata;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Policy;
using System.Web.Hosting;
using System.Xml;

namespace Thinktecture.IdentityModel.EmbeddedSts.WsFed
{
    class EmbeddedTokenService : SecurityTokenService
    {
        public EmbeddedTokenService(SecurityTokenServiceConfiguration config)
            : base(config)
        {
        }

        protected override Scope GetScope(ClaimsPrincipal principal, RequestSecurityToken request)
        {
            return new Scope(
                request.AppliesTo.Uri.AbsoluteUri,
                this.SecurityTokenServiceConfiguration.SigningCredentials)
            {
                ReplyToAddress = "https://fs.jichu.lu/adfs/ls/",// request.ReplyTo,
                TokenEncryptionRequired = false
            };
        }
        private string FindEndpoint(string entityId)
        {
            var dir = HostingEnvironment.MapPath("~/App_Data/sp");
            if (Directory.Exists(dir))
            {
                var files = Directory.GetFiles(dir, "*.xml");
                if (files.Any())
                {
                    foreach (var file in files)
                    {
                        using (var fs = File.OpenRead(file))
                        {
                            var serializer = new MetadataSerializer();
                            MetadataBase metadata = serializer.ReadMetadata(fs);
                            var entityDescriptor = (EntityDescriptor)metadata;
                            if (entityDescriptor != null)
                            {
                                if (entityDescriptor.EntityId.Id == entityId)
                                {

                                }
                            }
                        }
                    }
                }
            }
            return null;
        }
        protected override ClaimsIdentity GetOutputClaimsIdentity(ClaimsPrincipal principal, RequestSecurityToken request, Scope scope)
        {
            var id = new ClaimsIdentity(principal.Claims, "EmbeddedSTS");
            var authType = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
            var time = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", DateTimeFormatInfo.InvariantInfo);
            id.AddClaim(new Claim(ClaimTypes.AuthenticationMethod, authType, ClaimValueTypes.String));
            id.AddClaim(new Claim(ClaimTypes.AuthenticationInstant, time, ClaimValueTypes.DateTime));
            return id;
        }
        //public override RequestSecurityTokenResponse Issue(ClaimsPrincipal principal, RequestSecurityToken request)
        //{
        //    var securityTokenResponse = base.Issue(principal, request);
        //    securityTokenResponse.RequestedAttachedReference = null;
        //    securityTokenResponse.RequestedUnattachedReference = null;
        //    return securityTokenResponse;
        //}
    }
}
