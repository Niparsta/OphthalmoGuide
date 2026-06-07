using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Backend.Models;
using Backend.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace Backend.Services
{
    public class OphthalmologyService
    {
        private const int NormalPoints = 1;
        private const int RedFlagPoints = 3;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true
        };

        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;
        private readonly ILogger<OphthalmologyService> _logger;
        private readonly AppDbContext _dbContext;
        private readonly IConnectionMultiplexer _redis;

        private readonly string _ollamaUrl;
        private readonly string _modelName;

        public OphthalmologyService(
            HttpClient httpClient,
            IConfiguration configuration,
            ILogger<OphthalmologyService> logger,
            AppDbContext dbContext,
            IConnectionMultiplexer redis)
        {
            _httpClient = httpClient;
            _configuration = configuration;
            _logger = logger;
            _dbContext = dbContext;
            _redis = redis;

            _ollamaUrl = _configuration["Ollama:Url"] ?? "http://localhost:11434";
            _modelName = _configuration["Ollama:Model"] ?? "qwen3.5:4b-q4_K_M";
        }

        public async Task<OphthalmologyKnowledge> GetKnowledgeAsync()
        {
            var json = await _redis.GetDatabase().StringGetAsync(ValkeySeeder.KnowledgeKey);
            if (json.IsNullOrEmpty)
            {
                return new OphthalmologyKnowledge();
            }

            return JsonSerializer.Deserialize<OphthalmologyKnowledge>(json.ToString(), JsonOptions)
                   ?? new OphthalmologyKnowledge();
        }

        public async Task SaveKnowledgeAsync(OphthalmologyKnowledge knowledge)
        {
            await _redis.GetDatabase().StringSetAsync(
                ValkeySeeder.KnowledgeKey,
                JsonSerializer.Serialize(knowledge, JsonOptions));
        }

        public async Task<List<string>> GetSymptomsListAsync()
        {
            var knowledge = await GetKnowledgeAsync();
            return knowledge.Symptoms;
        }

        public async Task<List<DiseaseRecord>> GetDiseasesListAsync()
        {
            var knowledge = await GetKnowledgeAsync();
            return knowledge.Diseases;
        }

        public async Task<bool> SaveDataAsync(List<string> symptoms, List<DiseaseRecord> diseases)
        {
            await SaveKnowledgeAsync(new OphthalmologyKnowledge
            {
                Symptoms = symptoms,
                Diseases = diseases
            });
            return true;
        }


        public async Task<OllamaStatusResponse> CheckOllamaStatusAsync()
        {
            var result = new OllamaStatusResponse();
            try
            {
                var response = await _httpClient.GetAsync($"{_ollamaUrl.TrimEnd('/')}/api/tags");
                if (!response.IsSuccessStatusCode)
                {
                    result.Accessible = false;
                    result.Error = $"Ollama returned status code {response.StatusCode}";
                    return result;
                }

                using var jsonDoc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
                if (jsonDoc.RootElement.TryGetProperty("models", out var modelsElement) &&
                    modelsElement.ValueKind == JsonValueKind.Array)
                {
                    result.Accessible = true;
                    foreach (var model in modelsElement.EnumerateArray())
                    {
                        if (model.TryGetProperty("name", out var nameProp))
                        {
                            result.AvailableModels.Add(nameProp.GetString() ?? "");
                        }
                    }
                }
                else
                {
                    result.Accessible = true;
                    result.Error = "Accessed Ollama, but no models list found in response.";
                }
            }
            catch (Exception)
            {
                result.Accessible = false;
                result.Error = "Service connectivity check failed.";
            }

            return result;
        }

        public async Task<AnalyzeResponse> AnalyzeTextAsync(
            string text,
            CancellationToken cancellationToken = default)
        {
            var response = new AnalyzeResponse();
            if (string.IsNullOrWhiteSpace(text))
            {
                response.Success = false;
                response.Error = "Request text is empty.";
                return response;
            }

            var knowledge = await GetKnowledgeAsync();
            if (knowledge.Symptoms.Count == 0)
            {
                response.Success = false;
                response.Error = "Knowledge base is empty.";
                return response;
            }

            try
            {
                var llmResult = await ExtractSymptomsViaLlmAsync(text, knowledge.Symptoms, cancellationToken);
                if (!llmResult.Success)
                {
                    response.Success = false;
                    response.Error = llmResult.Error;
                    return response;
                }

                response.OllamaRawResponse = llmResult.RawResponse;
                response.ExtractedSymptoms = llmResult.Extracted;
                response.AssumedSymptoms = llmResult.Assumed;

                var allSymptoms = MergeSymptoms(llmResult.Extracted, llmResult.Assumed);
                response.Results = CalculateSymptomMatches(allSymptoms, knowledge);
                response.Success = true;
                return response;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Analysis failed.");
                response.Success = false;
                response.Error = "Analysis failed due to an internal error.";
                throw;
            }
        }


        public static List<DiseaseMatch> CalculateSymptomMatches(
            List<string> userSymptoms,
            OphthalmologyKnowledge knowledge)
        {
            var normalizedUserSymptoms = NormalizeSymptoms(userSymptoms, knowledge.Symptoms);

            if (normalizedUserSymptoms.Count == 0)
            {
                var healthy = knowledge.Diseases.FirstOrDefault(IsHealthyDisease);
                if (healthy == null)
                {
                    return new List<DiseaseMatch>();
                }

                return new List<DiseaseMatch>
                {
                    new()
                    {
                        Disease = healthy.Name,
                        ThreatLevel = healthy.ThreatLevel,
                        MatchingSymptomsCount = 0,
                        TotalDiseaseSymptomsCount = healthy.Symptoms.Count,
                        MatchPercentage = 100,
                        UserSymptomsCoverage = 100,
                        MatchedSymptoms = new(),
                        AllDiseaseSymptoms = healthy.Symptoms.Select(s => s.Name).ToList()
                    }
                };
            }

            var matches = new List<DiseaseMatch>();

            foreach (var disease in knowledge.Diseases)
            {
                if (IsHealthyDisease(disease) || disease.Symptoms.Count == 0)
                {
                    continue;
                }

                var symptomMap = disease.Symptoms.ToDictionary(
                    s => s.Name,
                    s => s.RedFlag ? RedFlagPoints : NormalPoints,
                    StringComparer.OrdinalIgnoreCase);

                var matched = normalizedUserSymptoms
                    .Where(s => symptomMap.ContainsKey(s))
                    .ToList();

                if (matched.Count == 0)
                {
                    continue;
                }

                double matchedPoints = matched.Sum(s => symptomMap[s]);
                double totalPoints = disease.Symptoms.Sum(s => s.RedFlag ? RedFlagPoints : NormalPoints);
                double matchPercentage = totalPoints > 0 ? matchedPoints / totalPoints * 100 : 0;
                double userCoverage = (double)matched.Count / normalizedUserSymptoms.Count * 100;

                matches.Add(new DiseaseMatch
                {
                    Disease = disease.Name,
                    ThreatLevel = disease.ThreatLevel,
                    MatchingSymptomsCount = matched.Count,
                    TotalDiseaseSymptomsCount = disease.Symptoms.Count,
                    MatchPercentage = Math.Round(matchPercentage, 1),
                    UserSymptomsCoverage = Math.Round(userCoverage, 1),
                    MatchedSymptoms = matched,
                    AllDiseaseSymptoms = disease.Symptoms.Select(s => s.Name).ToList()
                });
            }

            return matches
                .Where(m => m.MatchPercentage > 0)
                .OrderByDescending(m => m.MatchPercentage)
                .ThenByDescending(m => m.UserSymptomsCoverage)
                .ThenByDescending(m => m.MatchingSymptomsCount)
                .ThenByDescending(m => m.ThreatLevel)
                .ToList();
        }

        private static bool IsHealthyDisease(DiseaseRecord disease)
        {
            return disease.Symptoms.Count == 0 ||
                   disease.Name.Equals("Здоровый", StringComparison.OrdinalIgnoreCase);
        }

        private static List<string> NormalizeSymptoms(List<string> userSymptoms, List<string> validSymptoms)
        {
            return userSymptoms
                .Select(s => validSymptoms.FirstOrDefault(valid =>
                    valid.Equals(s, StringComparison.OrdinalIgnoreCase)))
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static List<string> MergeSymptoms(List<string> extracted, List<string> assumed)
        {
            var all = new List<string>(extracted);
            foreach (var s in assumed)
            {
                if (!all.Contains(s, StringComparer.OrdinalIgnoreCase))
                {
                    all.Add(s);
                }
            }

            return all;
        }

        private async Task<(bool Success, string? Error, string? RawResponse, List<string> Extracted, List<string> Assumed)>
            ExtractSymptomsViaLlmAsync(string text, List<string> symptomsList, CancellationToken cancellationToken)
        {
            var systemPrompt =
                "Вы — профессиональный офтальмологический помощник. " +
                "Вам дана жалоба пациента. Проанализируйте её контекст и выделите симптомы из предоставленного списка.\n" +
                "Ответьте строго в формате JSON-объекта:\n" +
                "{\n" +
                "  \"extracted\": [выделенные клинические симптомы — прямо упомянутые в жалобе],\n" +
                "  \"assumed\": [косвенные клинические симптомы — логически следующие из контекста, но не названные прямо]\n" +
                "}\n" +
                "Используйте только симптомы из списка. Только валидный JSON, без markdown и пояснений.";

            var userPrompt = $"Список допустимых симптомов:\n{string.Join("\n", symptomsList)}\n\nЖалоба пациента:\n\"{text}\"";

            var content = await CallOllamaChatAsync(systemPrompt, userPrompt, cancellationToken);
            if (content == null)
            {
                return (false, "AI analysis service temporarily unavailable.", null, new(), new());
            }

            var parsed = ParseStructuredResponseFromJson(content, symptomsList);
            return (true, null, content, parsed.Extracted, parsed.Assumed);
        }

        private async Task<string?> CallOllamaChatAsync(
            string systemPrompt,
            string userPrompt,
            CancellationToken cancellationToken)
        {
            var requestPayload = new
            {
                model = _modelName,
                messages = new[]
                {
                    new { role = "system", content = systemPrompt },
                    new { role = "user", content = userPrompt }
                },
                stream = false,
                think = false,
                options = new { temperature = 0.0 }
            };

            _logger.LogInformation("Sending request to Ollama: URL={Url}, Model={Model}", _ollamaUrl, _modelName);

            var ollamaResponse = await _httpClient.PostAsJsonAsync(
                $"{_ollamaUrl.TrimEnd('/')}/api/chat",
                requestPayload,
                cancellationToken);

            if (!ollamaResponse.IsSuccessStatusCode)
            {
                _logger.LogWarning("Ollama call failed with status: {StatusCode}", ollamaResponse.StatusCode);
                return null;
            }

            using var responseDoc = await JsonDocument.ParseAsync(
                await ollamaResponse.Content.ReadAsStreamAsync(cancellationToken),
                cancellationToken: cancellationToken);

            if (responseDoc.RootElement.TryGetProperty("message", out var messageObj) &&
                messageObj.TryGetProperty("content", out var contentObj))
            {
                return contentObj.GetString();
            }

            _logger.LogWarning("Ollama returned an unexpected response structure.");
            return null;
        }

        private (List<string> Extracted, List<string> Assumed) ParseStructuredResponseFromJson(
            string? json,
            List<string> validSymptoms)
        {
            var extracted = new List<string>();
            var assumed = new List<string>();

            if (string.IsNullOrWhiteSpace(json))
            {
                return (extracted, assumed);
            }

            try
            {
                var cleanedText = ExtractJsonObject(json);
                using var doc = JsonDocument.Parse(cleanedText);
                var root = doc.RootElement;

                if (root.TryGetProperty("extracted", out var extProp))
                {
                    AddSymptomsFromJsonElement(extProp, validSymptoms, extracted);
                }

                if (root.TryGetProperty("assumed", out var assProp))
                {
                    var parsedAssumed = new List<string>();
                    AddSymptomsFromJsonElement(assProp, validSymptoms, parsedAssumed);
                    foreach (var symptom in parsedAssumed)
                    {
                        if (!assumed.Contains(symptom, StringComparer.OrdinalIgnoreCase) &&
                            !extracted.Contains(symptom, StringComparer.OrdinalIgnoreCase))
                        {
                            assumed.Add(symptom);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse structured JSON from LLM: {Json}", json);
            }

            return (extracted, assumed);
        }

        private static string ExtractJsonObject(string json)
        {
            var cleanedText = Regex.Replace(json, @"<think>[\s\S]*?</think>", "").Trim();
            int startIndex = cleanedText.IndexOf('{');
            int endIndex = cleanedText.LastIndexOf('}');
            if (startIndex != -1 && endIndex != -1 && endIndex > startIndex)
            {
                return cleanedText.Substring(startIndex, endIndex - startIndex + 1);
            }

            return cleanedText;
        }

        private static void AddSymptomsFromJsonElement(JsonElement element, List<string> validSymptoms, List<string> target)
        {
            if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in element.EnumerateArray())
                {
                    AddValidSymptom(item.GetString(), validSymptoms, target);
                }
                return;
            }

            if (element.ValueKind == JsonValueKind.String)
            {
                AddValidSymptom(element.GetString(), validSymptoms, target);
            }
        }

        private static void AddValidSymptom(string? symptom, List<string> validSymptoms, List<string> target)
        {
            var value = symptom?.Trim();
            if (string.IsNullOrEmpty(value))
            {
                return;
            }

            var valid = validSymptoms.FirstOrDefault(v => v.Equals(value, StringComparison.OrdinalIgnoreCase));
            if (valid != null && !target.Contains(valid, StringComparer.OrdinalIgnoreCase))
            {
                target.Add(valid);
            }
        }

        public async Task<List<SessionHistoryRecord>> GetSessionHistoryAsync(string sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId)) return new();
            try
            {
                var entities = await _dbContext.SessionHistories
                    .Where(e => e.SessionId == sessionId)
                    .OrderByDescending(e => e.Timestamp)
                    .ToListAsync();

                return entities.Select(e => new SessionHistoryRecord
                {
                    Id = e.Id,
                    SessionId = e.SessionId,
                    Timestamp = e.Timestamp,
                    ComplaintText = e.ComplaintText,
                    DetectedSymptoms = e.DetectedSymptoms,
                    AssumedSymptoms = e.AssumedSymptoms,
                    Results = e.Results
                }).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve session history from storage.");
                return new();
            }
        }

        public async Task<List<SessionHistoryRecord>> GetAllSessionHistoryAsync(DateTime? from = null, DateTime? to = null)
        {
            try
            {
                var query = _dbContext.SessionHistories.AsQueryable();

                if (from.HasValue)
                {
                    query = query.Where(e => e.Timestamp >= from.Value.ToUniversalTime());
                }

                if (to.HasValue)
                {
                    query = query.Where(e => e.Timestamp <= to.Value.ToUniversalTime());
                }

                var entities = await query.OrderByDescending(e => e.Timestamp).ToListAsync();

                return entities.Select(e => new SessionHistoryRecord
                {
                    Id = e.Id,
                    SessionId = e.SessionId,
                    Timestamp = e.Timestamp,
                    ComplaintText = e.ComplaintText,
                    DetectedSymptoms = e.DetectedSymptoms,
                    AssumedSymptoms = e.AssumedSymptoms,
                    Results = e.Results
                }).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve all session history from storage.");
                return new();
            }
        }

        public async Task<string?> SaveSessionHistoryRecordAsync(
            string sessionId,
            string complaintText,
            List<string> detectedSymptoms,
            List<string> assumedSymptoms,
            List<DiseaseMatch> results)
        {
            if (string.IsNullOrWhiteSpace(sessionId)) return null;

            try
            {
                var id = Guid.NewGuid().ToString();
                _dbContext.SessionHistories.Add(new SessionHistoryEntity
                {
                    Id = id,
                    SessionId = sessionId,
                    Timestamp = DateTime.UtcNow,
                    ComplaintText = complaintText,
                    DetectedSymptoms = detectedSymptoms,
                    AssumedSymptoms = assumedSymptoms,
                    Results = results
                });
                await _dbContext.SaveChangesAsync();
                return id;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save session history to storage.");
                return null;
            }
        }



        public async Task<int> DeleteSessionHistoryRecordsAsync(System.Collections.Generic.List<string> ids)
        {
            if (ids == null || ids.Count == 0) return 0;

            return await _dbContext.SessionHistories
                .Where(e => ids.Contains(e.Id))
                .ExecuteDeleteAsync();
        }
    }
}
