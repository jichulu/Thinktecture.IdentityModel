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
using System.ServiceModel.Security;
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
            var replyToAddress = FindEndpoint(request.AppliesTo.Uri.ToString()) ?? request.ReplyTo;
            return new Scope(
                request.AppliesTo.Uri.AbsoluteUri,
                this.SecurityTokenServiceConfiguration.SigningCredentials)
            {
                ReplyToAddress = replyToAddress,
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
                            var serializer = new MetadataSerializer
                            {
                                CertificateValidationMode = X509CertificateValidationMode.None
                            };
                            MetadataBase metadata = serializer.ReadMetadata(fs);
                            var entityDescriptor = (EntityDescriptor)metadata;
                            if (entityDescriptor != null)
                            {
                                if (entityDescriptor.EntityId.Id == entityId)
                                {
                                    string PassiveRequestorEndpoint = null;
                                    string AssertionConsumerService = null;
                                    foreach (var item in entityDescriptor.RoleDescriptors)
                                    {
                                        if (item is SecurityTokenServiceDescriptor securityTokenServiceDescriptor)
                                        {
                                            PassiveRequestorEndpoint = securityTokenServiceDescriptor.PassiveRequestorEndpoints[0].Uri.ToString();
                                        }
                                        else if (item is ServiceProviderSingleSignOnDescriptor serviceProviderSingleSignOnDescriptor)
                                        {
                                            var endpoint = serviceProviderSingleSignOnDescriptor.AssertionConsumerServices.Default;
                                            AssertionConsumerService = endpoint.Location.ToString();
                                        }
                                    }
                                    return AssertionConsumerService ?? PassiveRequestorEndpoint;
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
            /*
             *   Supported SAML authentication context classes
             *
             *   Authentication method	Authentication context class URI
             *   User name and password	urn:oasis:names:tc:SAML:2.0:ac:classes:Password
             *   Password protected transport	urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
             *   Transport Layer Security (TLS) client	urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient
             *   X.509 certificate	urn:oasis:names:tc:SAML:2.0:ac:classes:X509
             *   Integrated Windows authentication	urn:federation:authentication:windows
             *   Kerberos	urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos
             */
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
