using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using StackExchange.Redis;

namespace Backend.Services
{
    public record TokenExchangeRequest(string Code, string RedirectUri);

    public static class OidcAuthService
    {
        public static IServiceCollection AddOidcAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            var authentikEnabled = configuration.GetValue<bool>("Authentik:Enabled", false);
            if (!authentikEnabled)
            {
                Console.WriteLine("[OIDC] Authentication is disabled. Admin features will bypass token validation.");
                services.AddAuthentication();
                services.AddAuthorization(options =>
                {
                    options.AddPolicy("AdminOnly", policy => policy.RequireAssertion(_ => true));
                });
                return services;
            }

            Console.WriteLine("[OIDC] Authentication is enabled. Configuring JwtBearer...");
            var authority = configuration["Authentik:Authority"] ?? "http://localhost:9000/application/o/ophthalmoguide/";
            var adminGroup = configuration["Authentik:AdminGroup"] ?? "ophthalmoguide Admins";

            // OpenID Connect Configuration Manager for dynamic discovery
            var metadataAddress = $"{authority.TrimEnd('/')}/.well-known/openid-configuration";
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = false }
            );

            services.AddSingleton<IConfigurationManager<OpenIdConnectConfiguration>>(configManager);

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.MapInboundClaims = false;
                    options.Authority = authority;
                    options.RequireHttpsMetadata = false;
                    options.ConfigurationManager = configManager;

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = true,
                        IssuerValidator = (issuer, securityToken, validationParameters) =>
                        {
                            if (string.IsNullOrEmpty(issuer))
                                throw new SecurityTokenInvalidIssuerException("Issuer is empty.");

                            var normalizedIssuer = NormalizeIssuer(issuer);
                            var normalizedAuthority = NormalizeIssuer(authority);

                            if (normalizedIssuer.Equals(normalizedAuthority, StringComparison.OrdinalIgnoreCase) ||
                                normalizedIssuer.EndsWith("/application/o/ophthalmoguide", StringComparison.OrdinalIgnoreCase))
                            {
                                return issuer;
                            }
                            throw new SecurityTokenInvalidIssuerException($"Issuer '{issuer}' is not valid.");
                        },
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ClockSkew = TimeSpan.FromSeconds(30)
                    };

                    options.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = context =>
                        {
                            var msg = context.Exception.Message;
                            if (context.Exception.InnerException != null)
                            {
                                msg += " | " + context.Exception.InnerException.Message;
                            }
                            context.Response.Headers["X-Auth-Error"] = msg;
                            Console.WriteLine($"[OIDC] Token validation failed: {msg}");
                            return Task.CompletedTask;
                        },
                        OnTokenValidated = async context =>
                        {
                            var identity = context.Principal?.Identity as System.Security.Claims.ClaimsIdentity;
                            if (identity == null) return;

                            var authHeader = context.Request.Headers["Authorization"].ToString();
                            var rawToken = authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) 
                                ? authHeader.Substring(7) 
                                : authHeader;

                            if (string.IsNullOrEmpty(rawToken)) return;

                            var jti = identity.FindFirst("jti")?.Value;
                            var sid = identity.FindFirst("sid")?.Value;
                            var sub = identity.FindFirst("sub")?.Value;

                            string tokenKey = jti ?? "";
                            if (string.IsNullOrEmpty(tokenKey))
                            {
                                using var sha256 = System.Security.Cryptography.SHA256.Create();
                                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawToken));
                                tokenKey = Convert.ToBase64String(hashBytes);
                            }

                            // Check Redis/Valkey for blacklisted session/token
                            var redis = context.HttpContext.RequestServices.GetService<IConnectionMultiplexer>();
                            IDatabase? db = null;
                            if (redis != null && redis.IsConnected)
                            {
                                db = redis.GetDatabase();

                                if (await db.KeyExistsAsync($"blacklist:token:{tokenKey}") ||
                                    (!string.IsNullOrEmpty(sid) && await db.KeyExistsAsync($"blacklist:session:{sid}")) ||
                                    (!string.IsNullOrEmpty(sub) && await db.KeyExistsAsync($"blacklist:user:{sub}")))
                                {
                                    Console.WriteLine($"[OIDC] Token validation failed: token/session is blacklisted.");
                                    context.Fail("Token/session is blacklisted.");
                                    return;
                                }

                                // Check active cache
                                if (await db.KeyExistsAsync($"active:token:{tokenKey}"))
                                {
                                    goto ProcessClaims;
                                }
                            }

                            // Fallback check: call Authentik userinfo endpoint
                            var authorityBase = authority.Split("/application/o/")[0];
                            var userinfoEndpoint = $"{authorityBase}/application/o/userinfo/";

                            try
                            {
                                using var client = new HttpClient();
                                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", rawToken);
                                var response = await client.GetAsync(userinfoEndpoint);

                                if (!response.IsSuccessStatusCode)
                                {
                                    // Только явный отказ Authentik (401/403) — сессия недействительна.
                                    // Сетевые/временные ошибки не должны ронять валидный JWT и вызывать цикл re-login на фронте.
                                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
                                        response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                                    {
                                        Console.WriteLine("[OIDC] Token validation failed: Session is inactive/revoked in Authentik.");
                                        context.Fail("Session is inactive or revoked.");

                                        if (db != null)
                                        {
                                            await db.StringSetAsync($"blacklist:token:{tokenKey}", "true", TimeSpan.FromMinutes(10));
                                        }
                                        return;
                                    }

                                    Console.WriteLine(
                                        $"[OIDC] Userinfo returned {(int)response.StatusCode}; skipping online check, trusting JWT signature.");
                                }
                                else if (db != null)
                                {
                                    await db.StringSetAsync($"active:token:{tokenKey}", "true", TimeSpan.FromSeconds(30));
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[OIDC] Userinfo validation failed with error: {ex.Message}. Bypassing to signature check.");
                            }

                        ProcessClaims:
                            // Map claims
                            var groupsClaims = identity.Claims
                                .Where(c => c.Type.Equals("groups", StringComparison.OrdinalIgnoreCase) || 
                                            c.Type.EndsWith("/groups", StringComparison.OrdinalIgnoreCase))
                                .ToList();

                            foreach (var claim in groupsClaims)
                            {
                                try
                                {
                                    var groups = JsonSerializer.Deserialize<string[]>(claim.Value);
                                    if (groups != null)
                                    {
                                        foreach (var group in groups)
                                        {
                                            if (!identity.HasClaim("authentik_group", group))
                                            {
                                                identity.AddClaim(new System.Security.Claims.Claim("authentik_group", group));
                                            }
                                        }
                                    }
                                }
                                catch
                                {
                                    if (!identity.HasClaim("authentik_group", claim.Value))
                                    {
                                        identity.AddClaim(new System.Security.Claims.Claim("authentik_group", claim.Value));
                                    }
                                }
                            }
                        }
                    };
                });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("AdminOnly", policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.RequireAssertion(context =>
                    {
                        return context.User.Claims.Any(c => 
                            (c.Type.Equals("authentik_group", StringComparison.OrdinalIgnoreCase) ||
                             c.Type.Equals("groups", StringComparison.OrdinalIgnoreCase) ||
                             c.Type.Equals("role", StringComparison.OrdinalIgnoreCase) ||
                             c.Type.Equals(System.Security.Claims.ClaimTypes.Role, StringComparison.OrdinalIgnoreCase)) &&
                            string.Equals(c.Value, adminGroup, StringComparison.OrdinalIgnoreCase));
                    });
                });
            });

            return services;
        }

        public static IEndpointRouteBuilder MapOidcEndpoints(this IEndpointRouteBuilder endpoints, IConfiguration config)
        {
            endpoints.MapPost("/api/auth/token", async (TokenExchangeRequest request, IHttpClientFactory httpClientFactory) =>
            {
                var authority = config["Authentik:Authority"] ?? "http://localhost:9000/application/o/ophthalmoguide/";
                var clientId = config["Authentik:ClientId"];
                var clientSecret = config["Authentik:ClientSecret"];
                
                var authorityBase = authority.Split("/application/o/")[0];
                var tokenEndpoint = $"{authorityBase}/application/o/token/";
                
                var client = httpClientFactory.CreateClient();
                var values = new Dictionary<string, string>
                {
                    { "grant_type", "authorization_code" },
                    { "code", request.Code },
                    { "redirect_uri", request.RedirectUri }
                };
                
                if (!string.IsNullOrEmpty(clientSecret) && clientSecret != "change-me-to-your-authentik-client-secret")
                {
                    var credentials = $"{clientId}:{clientSecret}";
                    var credentialsBytes = Encoding.UTF8.GetBytes(credentials);
                    var base64Credentials = Convert.ToBase64String(credentialsBytes);
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", base64Credentials);
                }
                else
                {
                    values.Add("client_id", clientId ?? "");
                }
                
                var reqContent = new FormUrlEncodedContent(values);
                var response = await client.PostAsync(tokenEndpoint, reqContent);
                var responseContent = await response.Content.ReadAsStringAsync();
                
                if (response.IsSuccessStatusCode)
                {
                    using var jsonDoc = JsonDocument.Parse(responseContent);
                    
                    string? accessToken = null;
                    string? idToken = null;
                    if (jsonDoc.RootElement.TryGetProperty("access_token", out var accessTokenProp))
                    {
                        accessToken = accessTokenProp.GetString();
                    }
                    if (jsonDoc.RootElement.TryGetProperty("id_token", out var idTokenProp))
                    {
                        idToken = idTokenProp.GetString();
                    }

                    if (!string.IsNullOrEmpty(accessToken))
                    {
                        return Results.Ok(new { access_token = accessToken, id_token = idToken });
                    }
                }
                
                Console.WriteLine($"[OIDC] Token exchange failed ({response.StatusCode}): {responseContent}");
                return Results.Problem($"Ошибка аутентификации. Проверьте Redirect URI в Authentik ({request.RedirectUri}).");
            })
            .WithName("ExchangeToken");

            endpoints.MapPost("/api/auth/logout", async (HttpContext context, IConnectionMultiplexer redis) =>
            {
                var authHeader = context.Request.Headers["Authorization"].ToString();
                var rawToken = authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                    ? authHeader.Substring(7)
                    : authHeader;

                if (string.IsNullOrEmpty(rawToken))
                {
                    return Results.Ok(new { message = "No active session." });
                }

                try
                {
                    var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                    if (handler.CanReadToken(rawToken))
                    {
                        var jwtToken = handler.ReadJwtToken(rawToken);
                        var jti = jwtToken.Id;

                        string tokenKey = jti;
                        if (string.IsNullOrEmpty(tokenKey))
                        {
                            using var sha256 = System.Security.Cryptography.SHA256.Create();
                            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawToken));
                            tokenKey = Convert.ToBase64String(hashBytes);
                        }

                        var exp = jwtToken.ValidTo;
                        var ttl = exp - DateTime.UtcNow;

                        var db = redis.GetDatabase();
                        if (ttl.TotalSeconds > 0)
                        {
                            await db.StringSetAsync($"blacklist:token:{tokenKey}", "true", ttl);
                        }

                        await db.KeyDeleteAsync($"active:token:{tokenKey}");
                    }

                    return Results.Ok(new { message = "Session invalidated successfully." });
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[OIDC] Error blacklisting token on logout: {ex.Message}");
                    return Results.Problem("Error processing logout.");
                }
            })
            .WithName("LogoutToken");

            endpoints.MapPost("/api/auth/backchannel-logout", async (HttpContext context, IConfiguration config, IConnectionMultiplexer redis, IConfigurationManager<OpenIdConnectConfiguration> configManager) =>
            {
                try
                {
                    var form = await context.Request.ReadFormAsync();
                    var logoutToken = form["logout_token"].ToString();
                    if (string.IsNullOrEmpty(logoutToken))
                    {
                        return Results.BadRequest("Missing logout_token.");
                    }

                    var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                    if (!handler.CanReadToken(logoutToken))
                    {
                        return Results.BadRequest("Invalid token format.");
                    }

                    var clientId = config["Authentik:ClientId"] ?? "ophthalmoguide";
                    var oidcConfig = await configManager.GetConfigurationAsync(context.RequestAborted);

                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = true,
                        ValidAudience = clientId,
                        ValidateIssuer = true,
                        ValidIssuer = oidcConfig.Issuer,
                        IssuerSigningKeys = oidcConfig.SigningKeys,
                        ValidateIssuerSigningKey = true,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromMinutes(1)
                    };

                    var principal = handler.ValidateToken(logoutToken, tokenValidationParameters, out var securityToken);
                    var jwtToken = securityToken as System.IdentityModel.Tokens.Jwt.JwtSecurityToken;
                    if (jwtToken == null)
                    {
                        return Results.BadRequest("Invalid security token.");
                    }

                    if (principal.HasClaim(c => c.Type == "nonce"))
                    {
                        return Results.BadRequest("Logout token must not contain a nonce.");
                    }

                    var sid = principal.FindFirst("sid")?.Value;
                    var sub = principal.FindFirst("sub")?.Value;

                    var db = redis.GetDatabase();
                    var exp = jwtToken.ValidTo;
                    var ttl = exp - DateTime.UtcNow;
                    if (ttl.TotalSeconds <= 0)
                    {
                        ttl = TimeSpan.FromMinutes(10);
                    }

                    if (!string.IsNullOrEmpty(sid))
                    {
                        await db.StringSetAsync($"blacklist:session:{sid}", "true", ttl);
                        Console.WriteLine($"[OIDC] Backchannel Logout: Session {sid} blacklisted for {ttl.TotalSeconds}s.");
                    }
                    if (!string.IsNullOrEmpty(sub))
                    {
                        await db.StringSetAsync($"blacklist:user:{sub}", "true", TimeSpan.FromMinutes(10));
                        Console.WriteLine($"[OIDC] Backchannel Logout: User {sub} blacklisted for 10 minutes.");
                    }

                    return Results.Ok();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[OIDC] Backchannel Logout validation failed: {ex.Message}");
                    return Results.BadRequest("Failed to process backchannel logout.");
                }
            })
            .WithName("BackchannelLogout");

            return endpoints;
        }

        private static string NormalizeIssuer(string issuer)
        {
            return issuer.Trim().TrimEnd('/');
        }
    }
}
