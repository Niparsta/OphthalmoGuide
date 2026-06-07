using bot_workerservice.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using StackExchange.Redis;
using Prometheus;

var builder = Host.CreateApplicationBuilder(args);

// Регистрация HttpClient для вызовов API бэкенда
builder.Services.AddHttpClient();

// Подключение к Valkey/Redis
builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var connStr = config["Redis:ConnectionString"] ?? "localhost:6379,abortConnect=false";
    return ConnectionMultiplexer.Connect(connStr);
});

// Регистрация фоновых сервисов ботов
builder.Services.AddHostedService<TelegramBotService>();
builder.Services.AddHostedService<VkBotService>();

// Старт сервера метрик Prometheus
var prometheusPort = builder.Configuration.GetValue<int>("Prometheus:Port", 8082);
var metricServer = new MetricServer(port: prometheusPort);
metricServer.Start();

var host = builder.Build();
host.Run();
