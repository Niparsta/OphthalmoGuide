using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
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
    public record TokenRefreshRequest(string? RefreshToken);
    public record LogoutRequest(string? RefreshToken);

    public static class OidcAuthService
    {
        private const string AccessTokenCookieName = "og_access_token";
        private const string RefreshTokenCookieName = "og_refresh_token";
        private static readonly TimeSpan RefreshLifetimeTtl = TimeSpan.FromDays(7);

        private enum ValkeySessionCheck
        {
            Allowed,
            Blacklisted,
            StoreUnavailable
        }

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
            var clientId = configuration["Authentik:ClientId"];

            // Determine whether to require HTTPS based on configuration or the authority URL scheme.
            var requireHttps = configuration.GetValue<bool>("Authentik:RequireHttpsMetadata", authority.StartsWith("https:", StringComparison.OrdinalIgnoreCase));

            // OpenID Connect Configuration Manager for dynamic discovery
            var metadataAddress = $"{authority.TrimEnd('/')}/.well-known/openid-configuration";
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = requireHttps }
            );

            services.AddSingleton<IConfigurationManager<OpenIdConnectConfiguration>>(configManager);

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.MapInboundClaims = false;
                    options.Authority = authority;
                    options.RequireHttpsMetadata = requireHttps;
                    options.ConfigurationManager = configManager;

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = !string.IsNullOrEmpty(clientId),
                        ValidAudience = clientId,
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
                        OnMessageReceived = context =>
                        {
                            var authHeader = context.Request.Headers["Authorization"].ToString();
                            if (string.IsNullOrEmpty(authHeader) && context.Request.Cookies.TryGetValue(AccessTokenCookieName, out var cookieToken))
                            {
                                context.Token = cookieToken;
                            }
                            return Task.CompletedTask;
                        },
                        OnAuthenticationFailed = context =>
                        {
                            var msg = context.Exception.Message;
                            if (context.Exception.InnerException != null)
                            {
                                msg += " | " + context.Exception.InnerException.Message;
                            }
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

                            if (string.IsNullOrEmpty(rawToken))
                            {
                                context.Request.Cookies.TryGetValue(AccessTokenCookieName, out rawToken);
                            }

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

                            // Check Redis/Valkey for blacklisted session/token (fail-closed if store is down)
                            var redis = context.HttpContext.RequestServices.GetService<IConnectionMultiplexer>();
                            if (!IsValkeyAvailable(redis))
                            {
                                Console.WriteLine("[OIDC] Token validation failed: Valkey is unavailable.");
                                context.Fail("Session store is unavailable.");
                                return;
                            }

                            var db = redis!.GetDatabase();

                            if (await db.KeyExistsAsync($"blacklist:token:{tokenKey}"))
                            {
                                Console.WriteLine($"[OIDC] Token validation failed: token {tokenKey} is blacklisted.");
                                context.Fail("Token is blacklisted.");
                                return;
                            }
                            if (!string.IsNullOrEmpty(sid) && await db.KeyExistsAsync($"blacklist:session:{sid}"))
                            {
                                Console.WriteLine($"[OIDC] Token validation failed: session {sid} is blacklisted.");
                                context.Fail("Session is blacklisted.");
                                return;
                            }

                            // Check active cache
                            if (await db.KeyExistsAsync($"active:token:{tokenKey}"))
                            {
                                goto ProcessClaims;
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
                                        Console.WriteLine($"[OIDC] Token validation failed: Session is inactive or revoked in Authentik. Blacklisting token {tokenKey} for 10m.");
                                        context.Fail("Session is inactive or revoked.");

                                        await db.StringSetAsync($"blacklist:token:{tokenKey}", "true", TimeSpan.FromMinutes(10));
                                        return;
                                    }

                                    Console.WriteLine(
                                        $"[OIDC] Userinfo returned {(int)response.StatusCode}; skipping online check, trusting JWT signature.");
                                }
                                else
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

                            // Safely log user information upon successful validation
                            var email = identity.FindFirst("email")?.Value;
                            var name = identity.FindFirst("preferred_username")?.Value ?? identity.FindFirst("name")?.Value;
                            Console.WriteLine($"[OIDC] Token validated successfully. User: {MaskUsername(name)} (Email: {MaskEmail(email)}, Sub: {sub}), Session SID: {sid}");
                        }
                    };
                });

            services.AddAuthorization(options =>
            {
                options.FallbackPolicy = new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme)
                    .RequireAuthenticatedUser()
                    .Build();

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
            endpoints.MapPost("/api/auth/token", async (HttpContext context, TokenExchangeRequest request, IConnectionMultiplexer redis, IHttpClientFactory httpClientFactory) =>
            {
                ClearAdminAuthCookies(context.Response);

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
                    string? refreshToken = null;
                    if (jsonDoc.RootElement.TryGetProperty("access_token", out var accessTokenProp))
                    {
                        accessToken = accessTokenProp.GetString();
                    }
                    if (jsonDoc.RootElement.TryGetProperty("refresh_token", out var refreshTokenProp))
                    {
                        refreshToken = refreshTokenProp.GetString();
                    }

                    if (!string.IsNullOrEmpty(accessToken))
                    {
                        try
                        {
                            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                            if (handler.CanReadToken(accessToken))
                            {
                                var jwt = handler.ReadJwtToken(accessToken);
                                var email = jwt.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
                                var name = jwt.Claims.FirstOrDefault(c => c.Type == "preferred_username" || c.Type == "name")?.Value;
                                var sub = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
                                Console.WriteLine($"[OIDC] Login successful. User: {MaskUsername(name)} (Email: {MaskEmail(email)}, Sub: {sub})");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[OIDC] Error parsing claims on login: {ex.Message}");
                        }

                        var sessionCheck = await CheckSessionBlacklistAsync(redis, GetJwtClaim(accessToken, "sid"));
                        if (sessionCheck == ValkeySessionCheck.StoreUnavailable)
                        {
                            Console.WriteLine("[OIDC] Token exchange rejected: Valkey is unavailable.");
                            ClearAdminAuthCookies(context.Response);
                            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                        }
                        if (sessionCheck == ValkeySessionCheck.Blacklisted)
                        {
                            var blockedSid = GetJwtClaim(accessToken, "sid");
                            Console.WriteLine($"[OIDC] Token exchange rejected: session {blockedSid} is blacklisted.");
                            if (!string.IsNullOrEmpty(refreshToken))
                            {
                                await RevokeTokenInAuthentik(refreshToken, "refresh_token", httpClientFactory, config);
                            }
                            ClearAdminAuthCookies(context.Response);
                            return Results.Unauthorized();
                        }

                        if (!await TryStoreRefreshSessionMappingAsync(redis, refreshToken, accessToken))
                        {
                            Console.WriteLine("[OIDC] Token exchange rejected: failed to store refresh session mapping.");
                            if (!string.IsNullOrEmpty(refreshToken))
                            {
                                await RevokeTokenInAuthentik(refreshToken, "refresh_token", httpClientFactory, config);
                            }
                            ClearAdminAuthCookies(context.Response);
                            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                        }

                        SetAdminAuthCookies(context.Response, accessToken, refreshToken);
                        return Results.Ok(new { success = true });
                    }
                }
                
                Console.WriteLine($"[OIDC] Token exchange failed ({response.StatusCode}): {responseContent}");
                ClearAdminAuthCookies(context.Response);
                return Results.Problem($"Ошибка аутентификации. Проверьте Redirect URI в Authentik ({request.RedirectUri}).");
            })
            .AllowAnonymous()
            .WithName("ExchangeToken");

            endpoints.MapPost("/api/auth/refresh", async (HttpContext context, TokenRefreshRequest? request, IConnectionMultiplexer redis, IHttpClientFactory httpClientFactory) =>
            {
                var authority = config["Authentik:Authority"] ?? "http://localhost:9000/application/o/ophthalmoguide/";
                var clientId = config["Authentik:ClientId"];
                var clientSecret = config["Authentik:ClientSecret"];
                
                var authorityBase = authority.Split("/application/o/")[0];
                var tokenEndpoint = $"{authorityBase}/application/o/token/";
                
                var client = httpClientFactory.CreateClient();
                var refreshToken = request?.RefreshToken;
                if (string.IsNullOrEmpty(refreshToken))
                {
                    context.Request.Cookies.TryGetValue(RefreshTokenCookieName, out refreshToken);
                }

                if (string.IsNullOrEmpty(refreshToken))
                {
                    ClearAdminAuthCookies(context.Response);
                    return Results.Unauthorized();
                }

                context.Request.Cookies.TryGetValue(AccessTokenCookieName, out var existingAccessToken);
                var preRefreshCheck = await CheckRefreshSessionAsync(redis, existingAccessToken, refreshToken);
                if (preRefreshCheck == ValkeySessionCheck.StoreUnavailable)
                {
                    Console.WriteLine("[OIDC] Refresh rejected: Valkey is unavailable.");
                    return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                }
                if (preRefreshCheck == ValkeySessionCheck.Blacklisted)
                {
                    var blockedSid = GetJwtClaim(existingAccessToken, "sid")
                        ?? await GetRefreshMappedSidAsync(redis, refreshToken);
                    await RejectBlacklistedRefreshAsync(
                        context, redis, httpClientFactory, config, refreshToken,
                        $"session {blockedSid} is blacklisted.");
                    return Results.Unauthorized();
                }

                var values = new Dictionary<string, string>
                {
                    { "grant_type", "refresh_token" },
                    { "refresh_token", refreshToken }
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
                    string? rotatedRefreshToken = null;
                    if (jsonDoc.RootElement.TryGetProperty("access_token", out var accessTokenProp))
                    {
                        accessToken = accessTokenProp.GetString();
                    }
                    if (jsonDoc.RootElement.TryGetProperty("refresh_token", out var refreshTokenProp))
                    {
                        rotatedRefreshToken = refreshTokenProp.GetString();
                    }

                    if (!string.IsNullOrEmpty(accessToken))
                    {
                        try
                        {
                            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                            if (handler.CanReadToken(accessToken))
                            {
                                var jwt = handler.ReadJwtToken(accessToken);
                                var email = jwt.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
                                var name = jwt.Claims.FirstOrDefault(c => c.Type == "preferred_username" || c.Type == "name")?.Value;
                                var sub = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
                                Console.WriteLine($"[OIDC] Token refreshed successfully. User: {MaskUsername(name)} (Email: {MaskEmail(email)}, Sub: {sub})");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[OIDC] Error parsing claims on refresh: {ex.Message}");
                        }

                        var effectiveRefreshToken = rotatedRefreshToken ?? refreshToken;
                        var postRefreshCheck = await CheckRefreshSessionAsync(redis, accessToken, effectiveRefreshToken);
                        if (postRefreshCheck == ValkeySessionCheck.StoreUnavailable)
                        {
                            Console.WriteLine("[OIDC] Refresh rejected after token exchange: Valkey is unavailable.");
                            await RevokeTokenInAuthentik(effectiveRefreshToken, "refresh_token", httpClientFactory, config);
                            ClearAdminAuthCookies(context.Response);
                            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                        }
                        if (postRefreshCheck == ValkeySessionCheck.Blacklisted)
                        {
                            await RejectBlacklistedRefreshAsync(
                                context, redis, httpClientFactory, config, effectiveRefreshToken,
                                $"session {GetJwtClaim(accessToken, "sid")} is blacklisted after refresh.");
                            return Results.Unauthorized();
                        }

                        if (!await IsAccessTokenActiveAtIdpAsync(accessToken, httpClientFactory, authority))
                        {
                            await RejectBlacklistedRefreshAsync(
                                context, redis, httpClientFactory, config, effectiveRefreshToken,
                                "session is inactive at IdP after refresh.");
                            return Results.Unauthorized();
                        }

                        if (!await TryStoreRefreshSessionMappingAsync(redis, effectiveRefreshToken, accessToken))
                        {
                            Console.WriteLine("[OIDC] Refresh rejected: failed to store refresh session mapping.");
                            await RevokeTokenInAuthentik(effectiveRefreshToken, "refresh_token", httpClientFactory, config);
                            ClearAdminAuthCookies(context.Response);
                            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                        }

                        SetAdminAuthCookies(context.Response, accessToken, effectiveRefreshToken);
                        return Results.Ok(new { success = true });
                    }
                }
                
                Console.WriteLine($"[OIDC] Token refresh failed ({response.StatusCode}): {responseContent}");
                ClearAdminAuthCookies(context.Response);
                return Results.Unauthorized();
            })
            .AllowAnonymous()
            .WithName("RefreshToken");

            endpoints.MapPost("/api/auth/logout", async (HttpContext context, LogoutRequest request, IConnectionMultiplexer redis, IHttpClientFactory httpClientFactory) =>
            {
                if (!IsValkeyAvailable(redis))
                {
                    Console.WriteLine("[OIDC] Logout failed: Valkey is unavailable.");
                    return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                }

                var authHeader = context.Request.Headers["Authorization"].ToString();
                var rawToken = authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                    ? authHeader.Substring(7)
                    : authHeader;

                if (string.IsNullOrEmpty(rawToken))
                {
                    context.Request.Cookies.TryGetValue(AccessTokenCookieName, out rawToken);
                }

                if (!string.IsNullOrEmpty(rawToken))
                {
                    try
                    {
                        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                        if (handler.CanReadToken(rawToken))
                        {
                            var jwtToken = handler.ReadJwtToken(rawToken);
                            var email = jwtToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
                            var name = jwtToken.Claims.FirstOrDefault(c => c.Type == "preferred_username" || c.Type == "name")?.Value;
                            var sub = jwtToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
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
                                 Console.WriteLine($"[OIDC] Logout: Token key {tokenKey} added to blacklist for {ttl.TotalSeconds}s.");
                            }

                            await db.KeyDeleteAsync($"active:token:{tokenKey}");

                            Console.WriteLine($"[OIDC] Logout successful. User: {MaskUsername(name)} (Email: {MaskEmail(email)}, Sub: {sub}), Revoked JTI: {tokenKey}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[OIDC] Error blacklisting token on logout: {ex.Message}");
                    }
                    
                    // Revoke Access Token in Authentik
                    await RevokeTokenInAuthentik(rawToken, "access_token", httpClientFactory, config);
                }

                var refreshToken = request?.RefreshToken;
                if (string.IsNullOrEmpty(refreshToken))
                {
                    context.Request.Cookies.TryGetValue(RefreshTokenCookieName, out refreshToken);
                }

                if (!string.IsNullOrEmpty(refreshToken))
                {
                    await ClearRefreshSessionMappingAsync(redis, refreshToken);
                    await RevokeTokenInAuthentik(refreshToken, "refresh_token", httpClientFactory, config);
                }

                ClearAdminAuthCookies(context.Response);

                return Results.Ok(new { message = "Session invalidated successfully." });
            })
            .AllowAnonymous()
            .WithName("LogoutToken");

            endpoints.MapPost("/api/auth/backchannel-logout", async (HttpContext context, IConfiguration config, IConnectionMultiplexer redis, IConfigurationManager<OpenIdConnectConfiguration> configManager) =>
            {
                if (!IsValkeyAvailable(redis))
                {
                    Console.WriteLine("[OIDC] Backchannel Logout failed: Valkey is unavailable.");
                    return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                }

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

                    // Validate events claim per OIDC Backchannel Logout 1.0 spec
                    var eventsClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "events")?.Value;
                    if (string.IsNullOrEmpty(eventsClaim) || !eventsClaim.Contains("http://schemas.openid.net/event/backchannel-logout"))
                    {
                        return Results.BadRequest("Invalid or missing events claim in logout token.");
                    }

                    if (principal.HasClaim(c => c.Type == "nonce"))
                    {
                        return Results.BadRequest("Logout token must not contain a nonce.");
                    }

                    var sid = principal.FindFirst("sid")?.Value;

                    var db = redis.GetDatabase();

                    if (!string.IsNullOrEmpty(sid))
                    {
                        await db.StringSetAsync($"blacklist:session:{sid}", "true", RefreshLifetimeTtl);
                        Console.WriteLine($"[OIDC] Backchannel Logout: Session {sid} blacklisted for {RefreshLifetimeTtl.TotalDays}d.");
                    }

                    return Results.Ok();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[OIDC] Backchannel Logout validation failed: {ex.Message}");
                    return Results.BadRequest("Failed to process backchannel logout.");
                }
            })
            .AllowAnonymous()
            .WithName("BackchannelLogout");

            return endpoints;
        }

        private static void SetAdminAuthCookies(HttpResponse response, string accessToken, string? refreshToken)
        {
            var accessMaxAge = GetJwtRemainingSeconds(accessToken);
            if (accessMaxAge > 0)
            {
                response.Cookies.Append(AccessTokenCookieName, accessToken, CreateAdminAccessCookieOptions(accessMaxAge));
            }

            if (!string.IsNullOrEmpty(refreshToken))
            {
                response.Cookies.Append(RefreshTokenCookieName, refreshToken, CreateAdminRefreshCookieOptions());
            }
        }

        private static void ClearAdminAuthCookies(HttpResponse response)
        {
            response.Cookies.Delete(AccessTokenCookieName, CreateAdminAccessCookieOptions(0));
            response.Cookies.Delete(RefreshTokenCookieName, CreateAdminRefreshCookieOptions(expire: true));
        }

        private static CookieOptions CreateAdminAccessCookieOptions(int maxAgeSeconds)
        {
            return new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Path = "/",
                MaxAge = maxAgeSeconds > 0 ? TimeSpan.FromSeconds(maxAgeSeconds) : TimeSpan.Zero
            };
        }

        private static CookieOptions CreateAdminRefreshCookieOptions(bool expire = false)
        {
            return new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                MaxAge = expire ? TimeSpan.Zero : null
            };
        }

        private static int GetJwtRemainingSeconds(string accessToken)
        {
            try
            {
                var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                if (!handler.CanReadToken(accessToken))
                {
                    return 3600;
                }

                var jwt = handler.ReadJwtToken(accessToken);
                var remaining = (int)Math.Floor((jwt.ValidTo - DateTime.UtcNow).TotalSeconds);
                return remaining > 0 ? remaining : 0;
            }
            catch
            {
                return 3600;
            }
        }

        private static string? GetJwtClaim(string? token, string claimType)
        {
            if (string.IsNullOrEmpty(token))
            {
                return null;
            }

            try
            {
                var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                if (!handler.CanReadToken(token))
                {
                    return null;
                }

                return handler.ReadJwtToken(token).Claims
                    .FirstOrDefault(c => c.Type == claimType)?.Value;
            }
            catch
            {
                return null;
            }
        }

        private static bool IsValkeyAvailable(IConnectionMultiplexer? redis)
            => redis is not null && redis.IsConnected;

        private static async Task<ValkeySessionCheck> CheckSessionBlacklistAsync(IConnectionMultiplexer? redis, string? sid)
        {
            if (!IsValkeyAvailable(redis))
            {
                return ValkeySessionCheck.StoreUnavailable;
            }

            if (string.IsNullOrEmpty(sid))
            {
                return ValkeySessionCheck.Allowed;
            }

            var blacklisted = await redis!.GetDatabase().KeyExistsAsync($"blacklist:session:{sid}");
            return blacklisted ? ValkeySessionCheck.Blacklisted : ValkeySessionCheck.Allowed;
        }

        private static async Task<ValkeySessionCheck> CheckRefreshSessionAsync(
            IConnectionMultiplexer? redis,
            string? accessToken,
            string? refreshToken)
        {
            if (!IsValkeyAvailable(redis))
            {
                return ValkeySessionCheck.StoreUnavailable;
            }

            var accessCheck = await CheckSessionBlacklistAsync(redis, GetJwtClaim(accessToken, "sid"));
            if (accessCheck != ValkeySessionCheck.Allowed)
            {
                return accessCheck;
            }

            if (string.IsNullOrEmpty(refreshToken))
            {
                return ValkeySessionCheck.Allowed;
            }

            var mappedSid = await GetRefreshMappedSidAsync(redis, refreshToken);
            return await CheckSessionBlacklistAsync(redis, mappedSid);
        }

        private static string GetTokenFingerprint(string token)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(hashBytes);
        }

        private static async Task<string?> GetRefreshMappedSidAsync(IConnectionMultiplexer? redis, string? refreshToken)
        {
            if (redis == null || !redis.IsConnected || string.IsNullOrEmpty(refreshToken))
            {
                return null;
            }

            var mappedSid = await redis.GetDatabase().StringGetAsync($"refresh_sid:{GetTokenFingerprint(refreshToken)}");
            return mappedSid.IsNullOrEmpty ? null : mappedSid.ToString();
        }

        private static async Task<bool> TryStoreRefreshSessionMappingAsync(
            IConnectionMultiplexer? redis,
            string? refreshToken,
            string? accessToken)
        {
            if (!IsValkeyAvailable(redis) || string.IsNullOrEmpty(refreshToken))
            {
                return false;
            }

            var sid = GetJwtClaim(accessToken, "sid");
            if (string.IsNullOrEmpty(sid))
            {
                return false;
            }

            var fp = GetTokenFingerprint(refreshToken);
            await redis!.GetDatabase().StringSetAsync($"refresh_sid:{fp}", sid, RefreshLifetimeTtl);
            return true;
        }

        private static async Task ClearRefreshSessionMappingAsync(IConnectionMultiplexer? redis, string? refreshToken)
        {
            if (!IsValkeyAvailable(redis) || string.IsNullOrEmpty(refreshToken))
            {
                return;
            }

            var fp = GetTokenFingerprint(refreshToken);
            await redis.GetDatabase().KeyDeleteAsync($"refresh_sid:{fp}");
        }

        private static async Task<bool> IsAccessTokenActiveAtIdpAsync(
            string accessToken,
            IHttpClientFactory httpClientFactory,
            string authority)
        {
            var authorityBase = authority.Split("/application/o/")[0];
            var userinfoEndpoint = $"{authorityBase}/application/o/userinfo/";

            try
            {
                using var client = httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                var response = await client.GetAsync(userinfoEndpoint);

                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
                    response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    return false;
                }

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[OIDC] Userinfo check on refresh failed: {ex.Message}");
                return true;
            }
        }

        private static async Task RejectBlacklistedRefreshAsync(
            HttpContext context,
            IConnectionMultiplexer? redis,
            IHttpClientFactory httpClientFactory,
            IConfiguration config,
            string? refreshToken,
            string reason)
        {
            Console.WriteLine($"[OIDC] Refresh rejected: {reason}");
            if (!string.IsNullOrEmpty(refreshToken))
            {
                await ClearRefreshSessionMappingAsync(redis, refreshToken);
                await RevokeTokenInAuthentik(refreshToken, "refresh_token", httpClientFactory, config);
            }

            ClearAdminAuthCookies(context.Response);
        }

        private static async Task RevokeTokenInAuthentik(string token, string tokenTypeHint, IHttpClientFactory httpClientFactory, IConfiguration config)
        {
            try
            {
                var authority = config["Authentik:Authority"] ?? "http://localhost:9000/application/o/ophthalmoguide/";
                var clientId = config["Authentik:ClientId"];
                var clientSecret = config["Authentik:ClientSecret"];
                
                var authorityBase = authority.Split("/application/o/")[0];
                var revokeEndpoint = $"{authorityBase}/application/o/revoke/";
                
                var client = httpClientFactory.CreateClient();
                var values = new Dictionary<string, string>
                {
                    { "token", token },
                    { "token_type_hint", tokenTypeHint }
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
                var response = await client.PostAsync(revokeEndpoint, reqContent);
                if (!response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"[OIDC] Token revocation failed for {tokenTypeHint} ({response.StatusCode}): {responseContent}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[OIDC] Exception during token revocation for {tokenTypeHint}: {ex.Message}");
            }
        }

        private static string NormalizeIssuer(string issuer)
        {
            return issuer.Trim().TrimEnd('/');
        }

        private static string MaskEmail(string? email)
        {
            if (string.IsNullOrEmpty(email)) return "unknown";
            var parts = email.Split('@');
            if (parts.Length != 2) return "***";
            var name = parts[0];
            var domain = parts[1];
            if (name.Length <= 2)
            {
                return $"***@{domain}";
            }
            return $"{name[0]}***{name[name.Length - 1]}@{domain}";
        }

        private static string MaskUsername(string? username)
        {
            if (string.IsNullOrEmpty(username)) return "unknown";
            if (username.Length <= 2) return "***";
            return $"{username[0]}***{username[username.Length - 1]}";
        }
    }
}
