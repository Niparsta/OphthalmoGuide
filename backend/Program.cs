using Backend;
using Backend.Models;
using Backend.Services;
using Backend.Data;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Builder;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Swashbuckle.AspNetCore.SwaggerUI;

// Загружаем секреты/хосты для локальной разработки из проектного .env
// (рядом с проектом). В Docker переменные приходят из docker-compose и имеют
// приоритет: значения из .env не перезаписывают уже заданные переменные окружения.
LoadDotEnv(Path.Combine(Directory.GetCurrentDirectory(), ".env"));
LoadDotEnv(Path.Combine(AppContext.BaseDirectory, ".env"));

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor | 
                                Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto |
                                Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedHost;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.AddOpenApi();
builder.Services.AddHttpClient();

// Configure OpenTelemetry for Prometheus scraping on a separate port
var prometheusPort = builder.Configuration["Prometheus:Port"] ?? "8081";
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics => metrics
        .AddAspNetCoreInstrumentation()
        .AddHttpClientInstrumentation()
        .AddPrometheusHttpListener(options =>
        {
            options.UriPrefixes = new[] { $"http://*:{prometheusPort}/" };
        }));

// Configure PostgreSQL with EF Core
var postgresConnectionString = builder.Configuration.GetConnectionString("DefaultConnection");
if (string.IsNullOrWhiteSpace(postgresConnectionString))
{
    postgresConnectionString = "Host=localhost;Database=postgres;Username=postgres;Password=postgres";
}
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(postgresConnectionString));

// Configure Valkey/Redis with resilient connection retries
var redisConnectionString = builder.Configuration["Redis:ConnectionString"] ?? "localhost:6379";
builder.Services.AddSingleton<IConnectionMultiplexer>(sp => 
{
    var options = ConfigurationOptions.Parse(redisConnectionString);
    options.AbortOnConnectFail = false; 
    options.ConnectRetry = 5;         
    return ConnectionMultiplexer.Connect(options);
});

// Register services
builder.Services.AddScoped<OphthalmologyService>();
builder.Services.AddSingleton<PdfExportService>();
builder.Services.AddTransient<OllamaQueueBroker>();
builder.Services.AddSingleton(sp => 
{
    var config = sp.GetRequiredService<IConfiguration>();
    var secret = config["Cap:Secret"] ?? "default_cap_secret_key_12345";
    return new backend.Services.CapService(secret);
});


// Configure CAP (DotNet Core CAP) using EntityFramework for Storage and Valkey/Redis Streams for Transport
builder.Services.AddCap(options =>
{
    options.UseEntityFramework<AppDbContext>();
    options.UseRedis(redisConnectionString);
});


// Configure Authentik Authentication and Authorization services
builder.Services.AddOidcAuthentication(builder.Configuration);
Console.WriteLine($"[Config DEBUG] Authentik:Authority = '{builder.Configuration["Authentik:Authority"]}'");

// Регистрация HTTP-клиента для SaluteSpeech.
builder.Services.AddHttpClient("SaluteSpeech")
    .ConfigurePrimaryHttpMessageHandler(sp =>
        CreateSaluteSpeechHandler(sp.GetRequiredService<IConfiguration>()));

builder.Services.AddSingleton<SaluteSpeechService>();

// Создаёт HttpMessageHandler только для SaluteSpeech с дополнительными корневыми сертификатами Минцифры
static HttpMessageHandler CreateSaluteSpeechHandler(IConfiguration configuration)
{
    var handler = new SocketsHttpHandler
    {
        AutomaticDecompression = DecompressionMethods.All,
        UseCookies = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5)
    };

    var extraRoots = LoadRussianTrustedCertificates();

    if (extraRoots.Count > 0)
    {
        handler.SslOptions = new SslClientAuthenticationOptions
        {
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            RemoteCertificateValidationCallback = (_, certificate, _, sslPolicyErrors) =>
                ValidateSaluteSpeechCertificate(certificate, extraRoots, sslPolicyErrors)
        };

        Console.WriteLine($"[SSL] SaluteSpeech HttpClient настроен с {extraRoots.Count} дополнительным(и) сертификатом(ами) Минцифры + принудительно TLS 1.2/1.3.");
    }
    else
    {
        var allowInsecureTls = configuration.GetValue<bool>("SaluteSpeech:AllowInsecureTls", false);
        if (allowInsecureTls)
        {
            // Explicit development-only escape hatch for local certificate troubleshooting.
            handler.SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            };
            Console.WriteLine("[SSL Warning] SaluteSpeech insecure TLS bypass is enabled by configuration.");
        }
        else
        {
            handler.SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            };
            Console.WriteLine("[SSL Warning] Certificates folder is empty or missing. Using system trust store only for SaluteSpeech.");
        }
    }

    return handler;
}

// Проверяет TLS-сертификат SaluteSpeech API: сначала системное хранилище, затем цепочку с сертификатами Минцифры
static bool ValidateSaluteSpeechCertificate(
    X509Certificate? certificate,
    X509Certificate2Collection extraRoots,
    SslPolicyErrors sslPolicyErrors)
{
    if (sslPolicyErrors == SslPolicyErrors.None)
        return true;

    if (certificate == null)
        return false;

    var cert2 = certificate as X509Certificate2 ?? new X509Certificate2(certificate);

    // Системное хранилище
    if (TryBuildCertificateChain(cert2, extraRoots, useCustomRoots: false, out var systemErrors))
        return true;

    // Корни Минцифры + промежуточные сертификаты в ExtraStore
    if (TryBuildCertificateChain(cert2, extraRoots, useCustomRoots: true, out var customErrors))
        return true;

    Console.WriteLine(
        $"[SSL] SaluteSpeech certificate validation failed. Policy errors: {sslPolicyErrors}. " +
        $"System chain: {systemErrors}. Custom chain: {customErrors}");
    return false;
}

static bool TryBuildCertificateChain(
    X509Certificate2 certificate,
    X509Certificate2Collection extraRoots,
    bool useCustomRoots,
    out string errors)
{
    using var chain = new X509Chain();
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    chain.ChainPolicy.VerificationTime = DateTime.UtcNow;

    if (useCustomRoots)
    {
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(extraRoots);
        chain.ChainPolicy.ExtraStore.AddRange(extraRoots);
    }

    var valid = chain.Build(certificate);
    errors = valid
        ? string.Empty
        : string.Join(", ", chain.ChainStatus.Select(s => s.StatusInformation?.Trim()));

    return valid;
}

// Загружает все .crt / .cer / .pem файлы из папки Certificates (рядом с приложением)
// Эти сертификаты используются ТОЛЬКО внутри контура этого приложения
static X509Certificate2Collection LoadRussianTrustedCertificates()
{
    var collection = new X509Certificate2Collection();

    var candidates = new[]
    {
        Path.Combine(AppContext.BaseDirectory, "Certificates"),
        Path.Combine(Directory.GetCurrentDirectory(), "Certificates"),
        Path.Combine(Directory.GetCurrentDirectory(), "backend/Certificates"),
        "/app/Certificates"
    };

    string? certDir = candidates.FirstOrDefault(Directory.Exists);

    if (certDir == null)
        return collection;

    var files = Directory.GetFiles(certDir, "*.*")
        .Where(f => f.EndsWith(".crt", StringComparison.OrdinalIgnoreCase) ||
                    f.EndsWith(".cer", StringComparison.OrdinalIgnoreCase) ||
                    f.EndsWith(".pem", StringComparison.OrdinalIgnoreCase))
        .ToArray();

    foreach (var file in files)
    {
        try
        {
            collection.Add(X509CertificateLoader.LoadCertificateFromFile(file));
            Console.WriteLine($"[SSL] Загружен дополнительный корневой сертификат: {Path.GetFileName(file)}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SSL Warning] Не удалось загрузить сертификат {Path.GetFileName(file)}: {ex.Message}");
        }
    }

    return collection;
}

var app = builder.Build();
app.UseForwardedHeaders();
var failOnStartupErrors = app.Configuration.GetValue("Startup:FailOnErrors", !app.Environment.IsDevelopment());
var requireSeedData = app.Configuration.GetValue("Startup:RequireSeedData", !app.Environment.IsDevelopment());
var valkeyWaitSeconds = app.Configuration.GetValue("Startup:ValkeyWaitSeconds", 60);

// Seed Valkey and Ensure Postgres schema at startup
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var logger = services.GetRequiredService<ILogger<Program>>();

    try
    {
        var redis = services.GetRequiredService<IConnectionMultiplexer>();
        EnsureValkeyReadyAsync(redis, logger, TimeSpan.FromSeconds(valkeyWaitSeconds)).GetAwaiter().GetResult();
    }
    catch (System.Exception ex)
    {
        logger.LogCritical(ex, "Valkey is not available.");
        if (failOnStartupErrors)
        {
            throw;
        }
    }
    
    // Ensure Postgres schema is created once at startup
    try
    {
        var dbContext = services.GetRequiredService<AppDbContext>();
        var databaseCreator = Microsoft.EntityFrameworkCore.Infrastructure.AccessorExtensions
            .GetService<Microsoft.EntityFrameworkCore.Storage.IDatabaseCreator>(dbContext.Database) 
            as Microsoft.EntityFrameworkCore.Storage.RelationalDatabaseCreator;
            
        if (databaseCreator != null)
        {
            if (!databaseCreator.Exists())
            {
                databaseCreator.Create();
            }
            
            bool tableExists = false;
            try
            {
                var conn = dbContext.Database.GetDbConnection();
                var wasOpen = conn.State == System.Data.ConnectionState.Open;
                if (!wasOpen) conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'session_history');";
                tableExists = (bool)(cmd.ExecuteScalar() ?? false);
                if (!wasOpen) conn.Close();
            }
            catch (System.Exception ex)
            {
                logger.LogWarning("Error checking table existence, falling back: {Message}", ex.Message);
            }

            if (!tableExists)
            {
                logger.LogInformation("Table 'session_history' not found. Generating and executing creation script...");
                var createScript = dbContext.Database.GenerateCreateScript();
                dbContext.Database.ExecuteSqlRaw(createScript);
                logger.LogInformation("Table 'session_history' created successfully.");
            }
            else
            {
                try
                {
                    dbContext.Database.ExecuteSqlRaw("ALTER TABLE session_history ADD COLUMN IF NOT EXISTS assumed_symptoms text NULL;");
                }
                catch (System.Exception ex)
                {
                    logger.LogWarning("Error adding column assumed_symptoms: {Message}", ex.Message);
                }
            }
        }
        else
        {
            dbContext.Database.EnsureCreated();
        }
        logger.LogInformation("Persistent storage schema verified successfully.");
    }
    catch (System.Exception ex)
    {
        logger.LogCritical(ex, "Failed to verify persistent database schema.");
        if (failOnStartupErrors)
        {
            throw;
        }
    }

    // Seed Valkey
    try
    {
        var redis = services.GetRequiredService<IConnectionMultiplexer>();
        
        var knowledgePath = "ophthalmology_knowledge.json";
        if (!File.Exists(knowledgePath))
        {
            knowledgePath = Path.Combine(AppContext.BaseDirectory, "ophthalmology_knowledge.json");
        }
        if (!File.Exists(knowledgePath))
        {
            knowledgePath = "../ophthalmology_knowledge.json";
        }
        if (!File.Exists(knowledgePath))
        {
            knowledgePath = "../../ophthalmology_knowledge.json";
        }

        if (!File.Exists(knowledgePath))
        {
            throw new FileNotFoundException("Knowledge JSON file was not found.", Path.GetFullPath(knowledgePath));
        }

        var seeded = ValkeySeeder.Seed(redis, Path.GetFullPath(knowledgePath), logger);
        if (seeded)
        {
            logger.LogInformation("Valkey seeded from knowledge file: {Path}", Path.GetFullPath(knowledgePath));
        }
        else
        {
            logger.LogInformation("Valkey key '{Key}' already contains data; seed from JSON skipped.", ValkeySeeder.KnowledgeKey);
        }
    }
    catch (System.Exception ex)
    {
        if (requireSeedData)
        {
            logger.LogCritical(ex, "Storage seeding failed.");
            throw;
        }

        logger.LogWarning("Storage seeding skipped or failed: {Message}", ex.Message);
    }
}

// Configure the HTTP request pipeline.
UseNoCacheForApiDocumentation(app);

app.MapOpenApi().AllowAnonymous();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/openapi/v1.json", "OphthalmoGuide API");
    options.RoutePrefix = "swagger";
});

UseApiGatewayPage(app);

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", async (AppDbContext dbContext, IConnectionMultiplexer redis) =>
{
    var databaseReady = await dbContext.Database.CanConnectAsync();
    var storageReady = redis.IsConnected;

    return databaseReady && storageReady
        ? Results.Ok(new { status = "healthy" })
        : Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
})
.AllowAnonymous()
.WithName("Health");

// API Endpoints
app.MapGet("/symptoms", async (OphthalmologyService service) =>
{
    try
    {
        var symptoms = await service.GetSymptomsListAsync();
        return Results.Ok(symptoms);
    }
    catch (System.Exception)
    {
        return Results.Problem("Внутренняя ошибка сервера. Попробуйте позже.");
    }
})
.RequireAuthorization("AdminOnly")
.WithName("GetSymptoms");

app.MapGet("/diseases", async (OphthalmologyService service) =>
{
    try
    {
        var diseases = await service.GetDiseasesListAsync();
        return Results.Ok(diseases);
    }
    catch (System.Exception)
    {
        return Results.Problem("Внутренняя ошибка сервера. Попробуйте позже.");
    }
})
.RequireAuthorization("AdminOnly")
.WithName("GetDiseases");

app.MapPost("/update-data", async (UpdateDataRequest request, OphthalmologyService service) =>
{
    try
    {
        var success = await service.SaveDataAsync(request.Symptoms, request.Diseases);
        return Results.Ok(new { success });
    }
    catch (System.Exception)
    {
        return Results.Problem("Внутренняя ошибка сервера. Попробуйте позже.");
    }
})
.WithName("UpdateData")
.RequireAuthorization("AdminOnly");

app.MapPost("/admin/knowledge/validate", (ValidateDataRequest request) =>
{
    try
    {
        var result = KnowledgeJsonValidator.Validate(request.Json);
        return Results.Ok(result);
    }
    catch (System.Exception ex)
    {
        return Results.BadRequest(new { errors = new List<string> { ex.Message } });
    }
})
.WithName("ValidateKnowledge")
.RequireAuthorization("AdminOnly");





app.MapOidcEndpoints(builder.Configuration);

app.MapGet("/admin/session", () => Results.Ok(new { authenticated = true }))
.WithName("ValidateAdminSession")
.RequireAuthorization("AdminOnly");

app.MapGet("/cap/challenge", (backend.Services.CapService capService) =>
{
    var challenge = capService.GenerateChallenge(50000);
    return Results.Ok(challenge);
})
.AllowAnonymous()
.WithName("GetCapChallenge");

app.MapPost("/analyze", async (HttpContext context, AnalyzeRequest request, OllamaQueueBroker broker, OphthalmologyService service, backend.Services.CapService capService, IConfiguration config, CancellationToken cancellationToken) =>
{
    var capCheck = await VerifyCapAsync(context, config, capService);
    if (capCheck != null) return capCheck;

    if (string.IsNullOrWhiteSpace(request.Text))
    {
        return Results.BadRequest(new AnalyzeResponse
        {
            Success = false,
            Error = "Complaint text cannot be empty."
        });
    }

    try
    {
        var sessionId = context.Request.Headers["Session-Id"].ToString();
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            sessionId = Guid.NewGuid().ToString(); // fallback
        }

        // Встаем в очередь через брокер
        var jobId = await broker.EnqueueAnalysisAsync(sessionId, request.Text);

        // Ожидаем выполнение задачи из очереди с таймаутом в 60 секунд
        var jobState = await broker.WaitForJobAsync(jobId, TimeSpan.FromSeconds(60), cancellationToken);

        if (jobState == null || jobState.Status == "Pending" || jobState.Status == "Processing")
        {
            return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
        }

        if (jobState.Status == "Failed" || jobState.Result == null)
        {
            return Results.Problem(jobState.Error ?? "Не удалось выполнить анализ.");
        }

        var result = jobState.Result;

        // Save to session history in storage if Session-Id was provided
        var originalSessionId = context.Request.Headers["Session-Id"].ToString();
        if (result.Success && !string.IsNullOrWhiteSpace(originalSessionId))
        {
            result.HistoryRecordId = await service.SaveSessionHistoryRecordAsync(
                originalSessionId, request.Text, result.ExtractedSymptoms, result.AssumedSymptoms, result.Results);
        }

        return Results.Ok(result);
    }
    catch (System.OperationCanceledException)
    {
        return Results.StatusCode(499);
    }
    catch (System.Exception)
    {
        return Results.Problem("Не удалось выполнить анализ. Попробуйте позже.");
    }
})
.AllowAnonymous()
.WithName("AnalyzeComplaint");


static IResult BuildPdfFileResult(byte[] pdfBytes)
{
    var reportTime = PdfExportService.ConvertUtcToMoscow(System.DateTime.UtcNow);
    return Results.File(pdfBytes, "application/pdf", PdfExportService.GetFileName(reportTime));
}

app.MapGet("/report/pdf", async (HttpContext context, string? id, AppDbContext dbContext, PdfExportService pdfService, backend.Services.CapService capService, IConfiguration config) =>
{
    var capCheck = await VerifyCapAsync(context, config, capService);
    if (capCheck != null) return capCheck;

    try
    {
        var sessionId = context.Request.Headers["Session-Id"].ToString();
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return Results.BadRequest("Session-Id header is required.");
        }

        SessionHistoryEntity? entity = null;
        if (!string.IsNullOrWhiteSpace(id))
        {
            entity = await dbContext.SessionHistories
                .FirstOrDefaultAsync(e => e.Id == id && e.SessionId == sessionId);
        }
        else
        {
            entity = await dbContext.SessionHistories
                .Where(e => e.SessionId == sessionId)
                .OrderByDescending(e => e.Timestamp)
                .FirstOrDefaultAsync();
        }

        if (entity == null)
        {
            return Results.NotFound("Запись сессии диагностики не найдена или доступ ограничен.");
        }

        var pdfBytes = pdfService.GenerateReportPdf(
            entity.Id,
            entity.Timestamp,
            entity.ComplaintText,
            entity.DetectedSymptoms,
            entity.AssumedSymptoms,
            entity.Results);

        return BuildPdfFileResult(pdfBytes);
    }
    catch (System.Exception)
    {
        return Results.Problem("Не удалось сформировать отчёт по данным из базы данных.");
    }
})
.AllowAnonymous()
.WithName("ExportPdfReport");


app.MapGet("/history", async (HttpContext context, OphthalmologyService service, backend.Services.CapService capService, IConfiguration config) =>
{
    var capCheck = await VerifyCapAsync(context, config, capService);
    if (capCheck != null) return capCheck;

    var sessionId = context.Request.Headers["Session-Id"].ToString();
    if (string.IsNullOrWhiteSpace(sessionId)) return Results.BadRequest("Session-Id header is required.");
    try
    {
        var history = await service.GetSessionHistoryAsync(sessionId);
        return Results.Ok(history);
    }
    catch (System.Exception)
    {
        return Results.Problem("Не удалось загрузить историю сессий.");
    }
})
.AllowAnonymous()
.WithName("GetSessionHistory");


app.MapGet("/admin/history", async (OphthalmologyService service, string? from, string? to) =>
{
    try
    {
        DateTime? fromUtc = null;
        DateTime? toUtc = null;

        if (!string.IsNullOrWhiteSpace(from) &&
            DateTime.TryParse(from, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var parsedFrom))
        {
            fromUtc = parsedFrom;
        }

        if (!string.IsNullOrWhiteSpace(to) &&
            DateTime.TryParse(to, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var parsedTo))
        {
            toUtc = parsedTo;
        }

        var history = await service.GetAllSessionHistoryAsync(fromUtc, toUtc);
        return Results.Ok(history);
    }
    catch (System.Exception)
    {
        return Results.Problem("Не удалось загрузить историю сессий.");
    }
})
.WithName("GetAllSessionHistory")
.RequireAuthorization("AdminOnly");


app.MapDelete("/admin/history/bulk", async ([Microsoft.AspNetCore.Mvc.FromBody] System.Collections.Generic.List<string> ids, OphthalmologyService service) =>
{
    try
    {
        var count = await service.DeleteSessionHistoryRecordsAsync(ids);
        return Results.Ok(new { success = true, count });
    }
    catch (System.Exception)
    {
        return Results.Problem("Не удалось удалить выбранные записи истории.");
    }
})
.WithName("DeleteSessionHistoryRecordsBulk")
.RequireAuthorization("AdminOnly");

// SaluteSpeech API: Распознавание речи (STT)
app.MapPost("/speech/recognize", async (HttpContext context, SaluteSpeechService speechService, ILogger<Program> logger, backend.Services.CapService capService, IConfiguration config) =>
{
    var capCheck = await VerifyCapAsync(context, config, capService);
    if (capCheck != null) return capCheck;

    try
    {
        using var ms = new MemoryStream();
        await context.Request.Body.CopyToAsync(ms);
        var audioBytes = ms.ToArray();

        if (audioBytes.Length == 0)
            return Results.BadRequest(new { error = "Audio data is empty." });

        var speechAudio = PrepareAudioForSaluteSpeech(audioBytes, context.Request.ContentType);

        var text = await speechService.RecognizeSpeechAsync(speechAudio.AudioBytes, speechAudio.ContentType);

        if (string.IsNullOrWhiteSpace(text))
        {
            logger.LogWarning("SaluteSpeech вернул пустой результат. Content-Type: {ContentType}, размер: {Length} байт.",
                speechAudio.ContentType, speechAudio.AudioBytes.Length);
        }

        return Results.Ok(new { success = true, text = text });
    }
    catch (InvalidDataException ex)
    {
        logger.LogWarning(ex, "Invalid audio data for speech recognition");
        return Results.BadRequest(new { error = "Некорректный формат аудио." });
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Speech recognition failed");
        return Results.Problem("Не удалось распознать речь.");
    }
})
.AllowAnonymous()
.WithName("RecognizeSpeech");

// Подготовка аудио под требования SaluteSpeech API
static (byte[] AudioBytes, string ContentType) PrepareAudioForSaluteSpeech(byte[] audioBytes, string? contentType)
{
    if (string.IsNullOrWhiteSpace(contentType))
        return (audioBytes, "audio/x-pcm;bit=16;rate=16000");

    var lower = contentType.ToLowerInvariant();

    if (lower.Contains("wav") || lower.Contains("wave"))
    {
        var wav = ExtractWavPcm(audioBytes);
        return (audioBytes, $"audio/x-pcm;bit={wav.BitsPerSample};rate={wav.SampleRate}");
    }

    if (lower.Contains("pcm"))
        return (audioBytes, "audio/x-pcm;bit=16;rate=16000");

    if (lower.Contains("webm"))
        return (audioBytes, "audio/ogg;codecs=opus");

    if (lower.Contains("ogg") && lower.Contains("opus"))
        return (audioBytes, "audio/ogg;codecs=opus");

    return (audioBytes, contentType);
}

static (byte[] PcmBytes, int SampleRate, int BitsPerSample) ExtractWavPcm(byte[] wavBytes)
{
    if (wavBytes.Length < 44 || !HasAscii(wavBytes, 0, "RIFF") || !HasAscii(wavBytes, 8, "WAVE"))
        throw new InvalidDataException("Audio body is not a valid WAV file.");

    int? audioFormat = null;
    int? channels = null;
    int? sampleRate = null;
    int? bitsPerSample = null;
    byte[]? pcmBytes = null;

    var offset = 12;
    while (offset + 8 <= wavBytes.Length)
    {
        var chunkId = System.Text.Encoding.ASCII.GetString(wavBytes, offset, 4);
        var chunkSize = BitConverter.ToInt32(wavBytes, offset + 4);
        var chunkDataOffset = offset + 8;

        if (chunkSize < 0 || chunkDataOffset + chunkSize > wavBytes.Length)
            throw new InvalidDataException("WAV chunk size is invalid.");

        if (chunkId == "fmt ")
        {
            if (chunkSize < 16)
                throw new InvalidDataException("WAV fmt chunk is invalid.");

            audioFormat = BitConverter.ToUInt16(wavBytes, chunkDataOffset);
            channels = BitConverter.ToUInt16(wavBytes, chunkDataOffset + 2);
            sampleRate = BitConverter.ToInt32(wavBytes, chunkDataOffset + 4);
            bitsPerSample = BitConverter.ToUInt16(wavBytes, chunkDataOffset + 14);
        }
        else if (chunkId == "data")
        {
            pcmBytes = wavBytes[chunkDataOffset..(chunkDataOffset + chunkSize)];
        }

        offset = chunkDataOffset + chunkSize + (chunkSize % 2);
    }

    if (audioFormat != 1)
        throw new InvalidDataException("Only PCM WAV audio is supported.");
    if (channels != 1)
        throw new InvalidDataException("Only mono WAV audio is supported.");
    if (bitsPerSample != 16)
        throw new InvalidDataException("Only 16-bit WAV audio is supported.");
    if (sampleRate is null or <= 0)
        throw new InvalidDataException("WAV sample rate is invalid.");
    if (pcmBytes is null || pcmBytes.Length == 0)
        throw new InvalidDataException("WAV data chunk is empty.");

    return (pcmBytes, sampleRate.Value, bitsPerSample.Value);
}

static bool HasAscii(byte[] bytes, int offset, string value)
{
    if (offset < 0 || offset + value.Length > bytes.Length)
        return false;

    for (var i = 0; i < value.Length; i++)
    {
        if (bytes[offset + i] != value[i])
            return false;
    }

    return true;
}

// SaluteSpeech API: Синтез речи (TTS)
app.MapPost("/speech/synthesize", async (HttpContext context, ILogger<Program> logger, backend.Services.CapService capService, IConfiguration config) =>
{
    var capCheck = await VerifyCapAsync(context, config, capService);
    if (capCheck != null) return capCheck;

    try
    {
        var speechService = context.RequestServices.GetRequiredService<SaluteSpeechService>();

        using var reader = new StreamReader(context.Request.Body);
        var body = await reader.ReadToEndAsync();
		
        string textToSynthesize;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(body);
            textToSynthesize = doc.RootElement.GetProperty("text").GetString() ?? "";
        }
        catch
        {
            textToSynthesize = body;
        }

        if (string.IsNullOrWhiteSpace(textToSynthesize))
            return Results.BadRequest(new { error = "Text is empty." });

        var audioBytes = await speechService.SynthesizeSpeechAsync(textToSynthesize);
        return Results.File(audioBytes, "audio/ogg", "speech.ogg");
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Speech synthesis failed");
        return Results.Problem("Не удалось синтезировать речь.");
    }
})
.AllowAnonymous()
.WithName("SynthesizeSpeech");

app.Run();

static void UseApiGatewayPage(WebApplication app)
{
    app.Use(async (context, next) =>
    {
        var path = context.Request.Path.Value;
        var isGatewayPath = path is "/" or "";
        var isSupportedMethod = HttpMethods.IsGet(context.Request.Method) ||
                                HttpMethods.IsHead(context.Request.Method);

        if (!isGatewayPath || !isSupportedMethod)
        {
            await next();
            return;
        }

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "text/plain; charset=utf-8";
        context.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate, max-age=0";

        if (HttpMethods.IsHead(context.Request.Method))
        {
            return;
        }

        await context.Response.WriteAsync("OphthalmoGuide API Gateway");
    });
}

static void UseNoCacheForApiDocumentation(WebApplication app)
{
    app.Use(async (context, next) =>
    {
        var path = context.Request.Path.Value ?? string.Empty;
        if (path.StartsWith("/swagger", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("/openapi", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.OnStarting(() =>
            {
                context.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate, max-age=0";
                context.Response.Headers.Pragma = "no-cache";
                context.Response.Headers.Expires = "0";
                return Task.CompletedTask;
            });
        }

        await next();
    });
}

static async Task EnsureValkeyReadyAsync(
    IConnectionMultiplexer redis,
    ILogger logger,
    TimeSpan timeout)
{
    var deadline = DateTime.UtcNow + timeout;

    while (DateTime.UtcNow < deadline)
    {
        try
        {
            if (!redis.IsConnected)
            {
                await Task.Delay(500);
                continue;
            }

            var latency = await redis.GetDatabase().PingAsync();
            logger.LogInformation("Valkey is ready (ping {LatencyMs:F1} ms).", latency.TotalMilliseconds);
            return;
        }
        catch (System.Exception ex)
        {
            logger.LogDebug("Valkey not ready yet: {Message}", ex.Message);
            await Task.Delay(500);
        }
    }

    throw new InvalidOperationException($"Valkey is not available after {timeout.TotalSeconds:F0}s.");
}

static void LoadDotEnv(string path)
{
    if (!File.Exists(path)) return;

    foreach (var rawLine in File.ReadAllLines(path))
    {
        var line = rawLine.Trim();
        if (line.Length == 0 || line.StartsWith('#')) continue;

        var separatorIndex = line.IndexOf('=');
        if (separatorIndex <= 0) continue;

        var key = line[..separatorIndex].Trim();
        var value = line[(separatorIndex + 1)..].Trim();

        if (value.Length >= 2 &&
            ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\'')))
        {
            value = value[1..^1];
        }

        if (Environment.GetEnvironmentVariable(key) is null)
        {
            Environment.SetEnvironmentVariable(key, value);
        }
    }
}

static async Task<IResult?> VerifyCapAsync(HttpContext context, IConfiguration config, backend.Services.CapService capService)
{
    var botKey = context.Request.Headers["X-Bot-Api-Key"].ToString();
    var configuredBotKey = config["Bot:ApiKey"] ?? "default_bot_api_key_abc123";
    if (!string.IsNullOrEmpty(botKey) && botKey == configuredBotKey)
    {
        return null;
    }

    var remoteIp = context.Connection.RemoteIpAddress;
    if (remoteIp != null && System.Net.IPAddress.IsLoopback(remoteIp))
    {
        return null;
    }

    var sessionId = context.Request.Headers["Session-Id"].ToString();
    if (string.IsNullOrWhiteSpace(sessionId))
    {
        sessionId = context.Request.Query["sessionId"].ToString();
    }

    var redis = context.RequestServices.GetService<StackExchange.Redis.IConnectionMultiplexer>();

    // 1. Check if we have a valid session verification token (Cap signature) in headers
    var capToken = context.Request.Headers["X-Cap-Token"].ToString();
    if (!string.IsNullOrWhiteSpace(capToken) && !string.IsNullOrWhiteSpace(sessionId) && redis != null && redis.IsConnected)
    {
        var db = redis.GetDatabase(1);
        var verifiedKey = $"session:verified:{sessionId}";
        var savedSignature = await db.StringGetAsync(verifiedKey);

        if (savedSignature.HasValue && string.Equals(savedSignature.ToString(), capToken, StringComparison.OrdinalIgnoreCase))
        {
            // Session is verified. Check session rate limits to prevent abuse (max 15 requests per 10 seconds)
            var unixTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var windowKey = $"session:rate:{sessionId}:{unixTime / 10}";

            var reqCount = await db.StringIncrementAsync(windowKey);
            if (reqCount == 1)
            {
                await db.KeyExpireAsync(windowKey, TimeSpan.FromSeconds(20));
            }

            if (reqCount > 15)
            {
                // Revoke trust due to rate limit abuse
                await db.KeyDeleteAsync(verifiedKey);
                return Results.Json(new { error = "Cap verification required due to rate limit", code = "cap_required" }, statusCode: 400);
            }

            return null; // Bypass full Cap challenge resolution check
        }
    }

    // 2. Fallback: Full verification of X-Cap-Payload
    var capPayloadToken = context.Request.Headers["X-Cap-Payload"].ToString();
    if (string.IsNullOrWhiteSpace(capPayloadToken))
    {
        capPayloadToken = context.Request.Query["capPayload"].ToString();
    }

    if (string.IsNullOrWhiteSpace(capPayloadToken))
    {
        return Results.Json(new { error = "Cap verification required", code = "cap_required" }, statusCode: 400);
    }

    try
    {
        var clientFactory = context.RequestServices.GetRequiredService<IHttpClientFactory>();
        using var client = clientFactory.CreateClient();

        var secret = config["Cap:Secret"] ?? "change_me_cap_secret_key_789abc";
        var siteKey = config["Cap:SiteKey"] ?? "f31d5d6959";
        var baseUrl = config["Cap:BaseUrl"] ?? "http://cap:3000";

        var verificationUrl = $"{baseUrl.TrimEnd('/')}/{siteKey}/siteverify";

        var verifyRequest = new { secret = secret, response = capPayloadToken };
        using var response = await client.PostAsJsonAsync(verificationUrl, verifyRequest);

        if (!response.IsSuccessStatusCode)
        {
            return Results.Json(new { error = "Cap verification failed", code = "cap_failed" }, statusCode: 400);
        }

        var result = await response.Content.ReadFromJsonAsync<CapVerificationResult>();
        if (result == null || !result.success)
        {
            return Results.Json(new { error = "Cap verification failed", code = "cap_failed" }, statusCode: 400);
        }

        // Replay Attack Protection is handled by Cap Standalone server itself.
        // We write the trusted session verification token to Redis to avoid re-verification for 15 minutes.
        if (redis != null && redis.IsConnected && !string.IsNullOrWhiteSpace(sessionId))
        {
            var db = redis.GetDatabase(1);
            var verifiedKey = $"session:verified:{sessionId}";
            await db.StringSetAsync(verifiedKey, capPayloadToken, TimeSpan.FromMinutes(15));
        }
    }
    catch (Exception ex)
    {
        return Results.Json(new { error = $"Cap verification failed: {ex.Message}", code = "cap_failed" }, statusCode: 400);
    }

    return null;
}

public class CapVerificationResult
{
    public bool success { get; set; }
}
