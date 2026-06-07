using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Backend.Models;
using DotNetCore.CAP;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace Backend.Services
{
    public class OllamaAnalysisMessage
    {
        public string JobId { get; set; } = string.Empty;
        public string SessionId { get; set; } = string.Empty;
        public string Text { get; set; } = string.Empty;
    }

    public class OllamaJobState
    {
        public string JobId { get; set; } = string.Empty;
        public string SessionId { get; set; } = string.Empty;
        public string Status { get; set; } = "Pending"; // Pending, Processing, Completed, Failed
        public string Text { get; set; } = string.Empty;
        public string? Error { get; set; }
        public AnalyzeResponse? Result { get; set; }
    }

    public class OllamaQueueBroker : ICapSubscribe
    {
        private readonly ICapPublisher _capPublisher;
        private readonly IConnectionMultiplexer _redis;
        private readonly OphthalmologyService _ophthalmologyService;
        private readonly ILogger<OllamaQueueBroker> _logger;

        private const string JobKeyPrefix = "ollama:job:";
        private const string PubSubChannelPrefix = "ollama:job:done:";
        private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

        public OllamaQueueBroker(
            ICapPublisher capPublisher,
            IConnectionMultiplexer redis,
            OphthalmologyService ophthalmologyService,
            ILogger<OllamaQueueBroker> logger)
        {
            _capPublisher = capPublisher;
            _redis = redis;
            _ophthalmologyService = ophthalmologyService;
            _logger = logger;
        }

        // Публикация запроса в очередь
        public async Task<string> EnqueueAnalysisAsync(string sessionId, string text)
        {
            var jobId = Guid.NewGuid().ToString();
            var state = new OllamaJobState
            {
                JobId = jobId,
                SessionId = sessionId,
                Status = "Pending",
                Text = text
            };

            var db = _redis.GetDatabase();
            await db.StringSetAsync($"{JobKeyPrefix}{jobId}", JsonSerializer.Serialize(state, JsonOptions), TimeSpan.FromHours(1));

            _logger.LogInformation("Enqueuing Ollama analysis job: JobId={JobId}, SessionId={SessionId}", jobId, sessionId);

            await _capPublisher.PublishAsync("ollama.analysis.request", new OllamaAnalysisMessage
            {
                JobId = jobId,
                SessionId = sessionId,
                Text = text
            });

            return jobId;
        }

        // Ожидание выполнения задачи через Pub/Sub с таймаутом
        public async Task<OllamaJobState?> WaitForJobAsync(string jobId, TimeSpan timeout, CancellationToken cancellationToken)
        {
            var db = _redis.GetDatabase();
            var jobKey = $"{JobKeyPrefix}{jobId}";

            // Проверяем, возможно задача уже завершилась до подписки
            var initialValue = await db.StringGetAsync(jobKey);
            if (!initialValue.IsNullOrEmpty)
            {
                var state = JsonSerializer.Deserialize<OllamaJobState>(initialValue.ToString(), JsonOptions);
                if (state != null && (state.Status == "Completed" || state.Status == "Failed"))
                {
                    return state;
                }
            }

            var tcs = new TaskCompletionSource<OllamaJobState?>(TaskCreationOptions.RunContinuationsAsynchronously);
            var channelName = $"{PubSubChannelPrefix}{jobId}";
            var subscriber = _redis.GetSubscriber();

            void Handler(RedisChannel channel, RedisValue value)
            {
                try
                {
                    var finishedState = JsonSerializer.Deserialize<OllamaJobState>(value.ToString(), JsonOptions);
                    tcs.TrySetResult(finishedState);
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            }

            await subscriber.SubscribeAsync(RedisChannel.Literal(channelName), Handler);

            try
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                var delayTask = Task.Delay(timeout, timeoutCts.Token);
                var completedTask = await Task.WhenAny(tcs.Task, delayTask);

                if (completedTask == tcs.Task)
                {
                    timeoutCts.Cancel();
                    return await tcs.Task;
                }
                else
                {
                    _logger.LogWarning("Timeout waiting for Ollama job completion: JobId={JobId}", jobId);
                    return null;
                }
            }
            finally
            {
                await subscriber.UnsubscribeAsync(RedisChannel.Literal(channelName), Handler);
            }
        }

        // Обработка сообщения из очереди (CAP Subscriber)
        [CapSubscribe("ollama.analysis.request")]
        public async Task ProcessAnalysisRequestAsync(OllamaAnalysisMessage message)
        {
            _logger.LogInformation("Processing Ollama analysis request from queue: JobId={JobId}, SessionId={SessionId}", message.JobId, message.SessionId);

            var db = _redis.GetDatabase();
            var jobKey = $"{JobKeyPrefix}{message.JobId}";

            var jobData = await db.StringGetAsync(jobKey);
            if (jobData.IsNullOrEmpty)
            {
                _logger.LogWarning("Job state not found in Valkey for JobId={JobId}", message.JobId);
                return;
            }

            var state = JsonSerializer.Deserialize<OllamaJobState>(jobData.ToString(), JsonOptions);
            if (state == null)
            {
                return;
            }

            state.Status = "Processing";
            await db.StringSetAsync(jobKey, JsonSerializer.Serialize(state, JsonOptions), TimeSpan.FromHours(1));

            try
            {
                // Вызываем сам сервис анализа, который делает HTTP-запрос к Ollama
                var result = await _ophthalmologyService.AnalyzeTextAsync(message.Text);

                state.Status = result.Success ? "Completed" : "Failed";
                state.Result = result;
                if (!result.Success)
                {
                    state.Error = result.Error;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing Ollama analysis for JobId={JobId}", message.JobId);
                state.Status = "Failed";
                state.Error = ex.Message;
            }

            // Записываем финальный статус в Valkey
            var updatedStateJson = JsonSerializer.Serialize(state, JsonOptions);
            await db.StringSetAsync(jobKey, updatedStateJson, TimeSpan.FromHours(1));

            // Публикуем уведомление в Pub/Sub для ожидающих запросов
            var channelName = $"{PubSubChannelPrefix}{message.JobId}";
            await _redis.GetSubscriber().PublishAsync(RedisChannel.Literal(channelName), updatedStateJson);
        }
    }
}
