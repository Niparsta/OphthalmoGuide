using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Backend.Services;


// Сервис интеграции с SaluteSpeech API
public class SaluteSpeechService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly ILogger<SaluteSpeechService> _logger;

    // Кэшированный токен доступа и время его истечения
    private string? _cachedAccessToken;
    private DateTimeOffset _tokenExpiresAt = DateTimeOffset.MinValue;
    private readonly SemaphoreSlim _tokenSemaphore = new(1, 1);

    // Кэш для результатов синтеза речи (TTS)
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte[]> _ttsCache = new();
    private readonly System.Collections.Concurrent.ConcurrentQueue<string> _ttsCacheKeys = new();
    private const int MaxTtsCacheSize = 100;

    public SaluteSpeechService(
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration,
        ILogger<SaluteSpeechService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _logger = logger;
    }

    // Получает актуальный access-токен, обновляя его при необходимости
    private async Task<string> GetAccessTokenAsync()
    {
        // Быстрая проверка без блокировки
        if (_cachedAccessToken != null && DateTimeOffset.UtcNow < _tokenExpiresAt.AddMinutes(-1))
        {
            return _cachedAccessToken;
        }

        await _tokenSemaphore.WaitAsync();
        try
        {
            // Повторная проверка после захвата семафора
            if (_cachedAccessToken != null && DateTimeOffset.UtcNow < _tokenExpiresAt.AddMinutes(-1))
            {
                return _cachedAccessToken;
            }

            _logger.LogInformation("Запрос нового access-токена SaluteSpeech...");

            var authKey = _configuration["SaluteSpeech:AuthorizationKey"]
                ?? throw new InvalidOperationException("Не задан ключ SaluteSpeech:AuthorizationKey в конфигурации.");

            var oauthUrl = _configuration["SaluteSpeech:OAuthUrl"]
                ?? "https://ngw.devices.sberbank.ru:9443/api/v2/oauth";

            var client = _httpClientFactory.CreateClient("SaluteSpeech");

            using var request = new HttpRequestMessage(HttpMethod.Post, oauthUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", authKey);
            request.Headers.Add("RqUID", Guid.NewGuid().ToString());
            request.Content = new StringContent("scope=SALUTE_SPEECH_PERS", Encoding.UTF8, "application/x-www-form-urlencoded");

            var response = await client.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Ошибка получения токена SaluteSpeech: {StatusCode} {Body}", response.StatusCode, responseBody);
                throw new HttpRequestException($"Ошибка OAuth SaluteSpeech: {response.StatusCode}");
            }

            using var doc = JsonDocument.Parse(responseBody);
            var root = doc.RootElement;

            _cachedAccessToken = root.GetProperty("access_token").GetString()
                ?? throw new InvalidOperationException("Поле access_token отсутствует в ответе OAuth.");

            var expiresAtMs = root.GetProperty("expires_at").GetInt64();
            _tokenExpiresAt = DateTimeOffset.FromUnixTimeMilliseconds(expiresAtMs);

            _logger.LogInformation("Токен SaluteSpeech получен, действителен до {ExpiresAt}", _tokenExpiresAt);

            return _cachedAccessToken;
        }
        finally
        {
            _tokenSemaphore.Release();
        }
    }

    // Распознаёт речь из аудиоданных (Speech-to-Text)
    public async Task<string> RecognizeSpeechAsync(byte[] audioBytes, string contentType)
    {
        var token = await GetAccessTokenAsync();

        var sttBaseUrl = _configuration["SaluteSpeech:SttUrl"]
            ?? "https://smartspeech.sber.ru/rest/v1/speech:recognize";

        var client = _httpClientFactory.CreateClient("SaluteSpeech");

        // Нормализуем Content-Type для SaluteSpeech API
        var targetContentType = NormalizeSttContentType(contentType);
        var requestUrl = BuildSttRequestUrl(sttBaseUrl, targetContentType);

        using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var byteContent = new ByteArrayContent(audioBytes);
        byteContent.Headers.ContentType = CreateSaluteSpeechMediaType(targetContentType);
        request.Content = byteContent;

        _logger.LogInformation(
            "Отправка аудио на распознавание ({Length} байт, исходный тип: {ContentType}, целевой тип: {TargetContentType}, URL: {RequestUrl})...",
            audioBytes.Length, contentType, targetContentType, requestUrl);

        var response = await client.SendAsync(request);
        var responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Ошибка STT SaluteSpeech: {StatusCode} {Body}", response.StatusCode, responseBody);
            throw new HttpRequestException($"Ошибка распознавания речи: {response.StatusCode}. {responseBody}");
        }

        _logger.LogDebug("Ответ STT: {Body}", responseBody);

        using var doc = JsonDocument.Parse(responseBody);
        var root = doc.RootElement;

        // Формат ответа: {"result": ["распознанный текст"], "status": 200}
        if (root.TryGetProperty("result", out var resultArray) && resultArray.GetArrayLength() > 0)
        {
            var recognizedText = resultArray[0].GetString() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(recognizedText))
            {
                _logger.LogWarning("SaluteSpeech вернул пустую строку в result. Ответ: {Body}", responseBody);
            }
            else
            {
                _logger.LogInformation("Распознанный текст: {Text}", recognizedText);
            }
            return recognizedText;
        }

        _logger.LogWarning("SaluteSpeech вернул ответ без result. Тело: {Body}", responseBody);
        return string.Empty;
    }

    private static string NormalizeSttContentType(string contentType)
    {
        var lower = contentType.ToLowerInvariant();
        if (lower.Contains("wav") || lower.Contains("wave"))
            return "audio/x-pcm;bit=16;rate=16000";

        if (lower.Contains("pcm") && !lower.Contains("rate="))
            return "audio/x-pcm;bit=16;rate=16000";

        if (lower.Contains("webm"))
            return "audio/ogg;codecs=opus";

        if (lower.Contains("ogg") && lower.Contains("opus"))
            return "audio/ogg;codecs=opus";

        return contentType;
    }

    // Для raw PCM без WAV-заголовка SaluteSpeech API требует query-параметр sample_rate
    private static string BuildSttRequestUrl(string baseUrl, string targetContentType)
    {
        var queryParams = new List<string> { "language=ru-RU", "enable_profanity_filter=false" };
        var lower = targetContentType.ToLowerInvariant();

        if (lower.Contains("pcm"))
        {
            var sampleRate = ExtractSampleRate(targetContentType) ?? 16000;
            queryParams.Add($"sample_rate={sampleRate}");
            queryParams.Add("channels_count=1");
        }

        var separator = baseUrl.Contains('?') ? "&" : "?";
        return $"{baseUrl}{separator}{string.Join("&", queryParams)}";
    }

    private static int? ExtractSampleRate(string contentType)
    {
        var match = Regex.Match(contentType, @"rate=(\d+)", RegexOptions.IgnoreCase);
        return match.Success && int.TryParse(match.Groups[1].Value, out var rate) ? rate : null;
    }

    private static MediaTypeHeaderValue CreateSaluteSpeechMediaType(string contentType)
    {
        var parts = contentType.Split(';', 2, StringSplitOptions.TrimEntries);
        var mediaType = new MediaTypeHeaderValue(parts[0]);

        if (parts.Length > 1)
        {
            foreach (var segment in parts[1].Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var eq = segment.IndexOf('=');
                if (eq > 0)
                {
                    mediaType.Parameters.Add(new NameValueHeaderValue(
                        segment[..eq].Trim(),
                        segment[(eq + 1)..].Trim().Trim('"')));
                }
            }
        }

        return mediaType;
    }

    // Синтезирует речь из текста (Text-to-Speech)
    public async Task<byte[]> SynthesizeSpeechAsync(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return Array.Empty<byte>();
        }

        // Проверяем кэш, если текст повторяется
        if (_ttsCache.TryGetValue(text, out var cachedAudio))
        {
            _logger.LogInformation("Возвращаем аудио из кэша для текста ({Length} символов)...", text.Length);
            return cachedAudio;
        }

        var token = await GetAccessTokenAsync();

        var ttsBaseUrl = _configuration["SaluteSpeech:TtsUrl"]
            ?? "https://smartspeech.sber.ru/rest/v1/text:synthesize";
        var voice = _configuration["SaluteSpeech:TtsVoice"] ?? "Nec_24000";
        var format = _configuration["SaluteSpeech:TtsFormat"] ?? "opus";

        var ttsUrl = $"{ttsBaseUrl}?format={format}&voice={voice}";

        var client = _httpClientFactory.CreateClient("SaluteSpeech");

        using var request = new HttpRequestMessage(HttpMethod.Post, ttsUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        
        // Используем ByteArrayContent вместо StringContent, чтобы избежать автоматического 
        // добавления параметра "charset=utf-8", который строго отвергается API SaluteSpeech.
        var textBytes = Encoding.UTF8.GetBytes(text);
        request.Content = new ByteArrayContent(textBytes);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/text");

        _logger.LogInformation("Отправка текста на синтез речи ({Length} символов)...", text.Length);

        var response = await client.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync();
            _logger.LogError("Ошибка TTS SaluteSpeech: {StatusCode} {Body}", response.StatusCode, errorBody);
            throw new HttpRequestException($"Ошибка синтеза речи: {response.StatusCode}");
        }

        var audioBytes = await response.Content.ReadAsByteArrayAsync();
        _logger.LogInformation("Синтез речи завершён, получено {Length} байт аудио.", audioBytes.Length);

        // Сохраняем в кэш с ограничением максимального размера
        while (_ttsCacheKeys.Count >= MaxTtsCacheSize)
        {
            if (_ttsCacheKeys.TryDequeue(out var oldestKey))
            {
                _ttsCache.TryRemove(oldestKey, out _);
            }
        }
        if (_ttsCache.TryAdd(text, audioBytes))
        {
            _ttsCacheKeys.Enqueue(text);
        }

        return audioBytes;
    }
}
