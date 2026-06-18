using bot_workerservice.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using StackExchange.Redis;
using Prometheus;

var builder = Host.CreateApplicationBuilder(args);

// Регистрация HttpClient для вызовов API бэкенда с API-ключом авторизации ботов для обхода Altcha
builder.Services.AddHttpClient(string.Empty, client =>
{
    var apiKey = builder.Configuration["Bot:ApiKey"] ?? "default_bot_api_key_abc123";
    client.DefaultRequestHeaders.Add("X-Bot-Api-Key", apiKey);
});

// Подключение к Valkey/Redis
builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var connStr = config["Redis:ConnectionString"] ?? "localhost:6379,abortConnect=false";
    return ConnectionMultiplexer.Connect(connStr);
});

// Регистрация лимитера запросов ботов
builder.Services.AddSingleton<BotRateLimiter>();

// Регистрация фоновых сервисов ботов
builder.Services.AddHostedService<TelegramBotService>();
builder.Services.AddHostedService<VkBotService>();

// Старт сервера метрик Prometheus
var prometheusPort = builder.Configuration.GetValue<int>("Prometheus:Port", 8082);
var metricServer = new MetricServer(port: prometheusPort);
metricServer.Start();

var host = builder.Build();
host.Run();
