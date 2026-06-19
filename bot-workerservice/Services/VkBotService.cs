using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;
using VkNet;
using VkNet.Enums.StringEnums;
using VkNet.Model;
using VkNet.Utils;

namespace bot_workerservice.Services
{
    public class VkBotService : BackgroundService
    {
        private readonly ILogger<VkBotService> _logger;
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConnectionMultiplexer _redis;

        private VkApi? _vk;
        private string _backendUrl = "http://localhost:5190";
        private HashSet<long> _allowedUserIds = new();
        private bool _restrictAccess;
        private ulong _groupId;

        private const string DisclaimerText =
            "⚠️ Дисклеймер\n\n" +
            "Сервис носит исключительно информационно-справочный характер и не является медицинским изделием " +
            "или системой поддержки принятия врачебных решений. Представленные сведения не являются диагнозом, " +
            "назначением или руководством к самолечению и не заменяют очную консультацию квалифицированного специалиста. " +
            "Полнота и точность представленной информации не гарантируются; ответственность за её самостоятельную " +
            "интерпретацию и принятые на её основе решения несёт пользователь. При любых симптомах обратитесь " +
            "к врачу соотвествующего профиля, а в неотложных случаях – вызовите скорую медицинскую помощь (112/103)." +
            "\n\nВы согласны с условиями использования?";

        private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

        private readonly BotRateLimiter _rateLimiter;

        public VkBotService(
            ILogger<VkBotService> logger,
            IConfiguration configuration,
            IHttpClientFactory httpClientFactory,
            IConnectionMultiplexer redis,
            BotRateLimiter rateLimiter)
        {
            _logger = logger;
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
            _redis = redis;
            _rateLimiter = rateLimiter;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var token = _configuration["Vk:Token"];
            var gidStr = _configuration["Vk:GroupId"];
            if (string.IsNullOrWhiteSpace(token))
            {
                _logger.LogWarning("[VK] VK Token is not configured. Service will not start.");
                return;
            }

            _vk = new VkApi();
            await _vk.AuthorizeAsync(new ApiAuthParams { AccessToken = token });

            if (!ulong.TryParse(gidStr, out _groupId) || _groupId == 0)
            {
                _logger.LogInformation("[VK] GroupId is not configured or is 0. Fetching automatically from VK API...");
                try
                {
                    var groups = await _vk.Groups.GetByIdAsync(null, null, null);
                    var group = groups.FirstOrDefault();
                    if (group != null)
                    {
                        _groupId = (ulong)group.Id;
                        _logger.LogInformation("[VK] Automatically detected GroupId: {GroupId} ({GroupName})", _groupId, group.Name);
                    }
                    else
                    {
                        _logger.LogError("[VK] Failed to automatically detect GroupId: API returned an empty list.");
                        return;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[VK] Failed to automatically detect GroupId");
                    return;
                }
            }

            _backendUrl = (_configuration["Backend:Url"] ?? _backendUrl).TrimEnd('/');

            var ids = _configuration["Vk:AllowedUserIds"];
            if (!string.IsNullOrWhiteSpace(ids))
            {
                _allowedUserIds = ids.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(long.Parse).ToHashSet();
                _restrictAccess = true;
                _logger.LogInformation("[VK] Access restricted to {Count} user(s).", _allowedUserIds.Count);
            }

            _logger.LogInformation("[VK] Bot authorized for group {GroupId}.", _groupId);

            await LongPollLoopAsync(stoppingToken);
        }

        // ──────────── Long Poll ────────────

        private async Task LongPollLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var srv = await _vk!.Groups.GetLongPollServerAsync(_groupId);
                    var ts = srv.Ts;

                    while (!ct.IsCancellationRequested)
                    {
                        BotsLongPollHistoryResponse poll;
                        try
                        {
                            poll = await _vk.Groups.GetBotsLongPollHistoryAsync(
                                new BotsLongPollHistoryParams
                                {
                                    Server = srv.Server, Key = srv.Key, Ts = ts, Wait = 25
                                });
                        }
                        catch
                        {
                            _logger.LogWarning("[VK] LP key expired, reconnecting…");
                            break;
                        }

                        ts = poll.Ts;
                        if (poll.Updates == null) continue;

                        foreach (var upd in poll.Updates)
                        {
                            try
                            {
                                if (upd.Instance is MessageNew messageNew)
                                {
                                    var message = messageNew.Message;
                                    if (message != null)
                                        await OnMessageAsync(message, ct);
                                }
                            }
                            catch (Exception updEx)
                            {
                                _logger.LogError(updEx, "[VK] Error processing update in loop");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[VK] LP loop error, retry in 5 s…");
                    await Task.Delay(5000, ct);
                }
            }
        }

        // ──────────── Обработка сообщений ────────────

        private async Task OnMessageAsync(Message msg, CancellationToken ct)
        {
            if (msg.FromId == null) return;
            long userId = msg.FromId.Value;

            if (_restrictAccess && !_allowedUserIds.Contains(userId)) return;

            try
            {
                if (await ProcessRateLimitAsync(userId, msg, ct))
                {
                    return;
                }

                var text  = msg.Text?.Trim() ?? "";
                var db    = _redis.GetDatabase();
                var stKey = $"bot:vk:state:{userId}";
                var sesKey = $"bot:vk:session:{userId}";
                var state = (string?)await db.StringGetAsync(stKey);

                // 1. Payload кнопок (VK отправляет payload в message.Payload)
                if (!string.IsNullOrEmpty(msg.Payload))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(msg.Payload);
                        // Кнопки дисклеймера: payload = {"button":"agree"} / {"button":"disagree"}
                        if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                            doc.RootElement.TryGetProperty("button", out var btnProp))
                        {
                            var val = btnProp.GetString();
                            if (val == "agree")
                            {
                                if (state != "disclaimer")
                                {
                                    await SendAsync(userId, "Для начала работы примите дисклеймер – напишите \"Начать\".");
                                    return;
                                }
                                await NewSession(db, stKey, sesKey, userId);
                                await SendAsync(userId, "✅ Спасибо!\n\nРасскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.", ClearKeyboard());
                                return;
                            }
                            if (val == "disagree")
                            {
                                if (state != "disclaimer")
                                {
                                    await SendAsync(userId, "Для начала работы примите дисклеймер – напишите \"Начать\".");
                                    return;
                                }
                                await db.StringSetAsync(stKey, "disclaimer");
                                await SendAsync(userId, "❌ Без согласия диагностика невозможна. Напишите \"Начать\", чтобы вернуться к соглашению.");
                                return;
                            }
                            if (val == "restart" || val == "clear")
                            {
                                if (state != "active" && state != "results")
                                {
                                    await SendAsync(userId, "Для начала работы примите дисклеймер – напишите \"Начать\".");
                                    return;
                                }
                                await RestartSessionAsync(userId, db, stKey, sesKey);
                                return;
                            }
                        }

                        // Кнопка PDF: payload = {"cmd":"pdf","id":"..."}
                        if (doc.RootElement.TryGetProperty("cmd", out var cmd) && cmd.GetString() == "pdf" &&
                            doc.RootElement.TryGetProperty("id", out var idProp))
                        {
                            if (state != "active" && state != "results")
                            {
                                await SendAsync(userId, "Для начала работы примите дисклеймер – напишите \"Начать\".");
                                return;
                            }
                            var recordId  = idProp.GetString();
                            var sessionId = (string?)await db.StringGetAsync(sesKey);
                            await SendAsync(userId, "📥 Формирую отчёт…");

                             var (pdfStream, filename) = await DownloadPdfAsync(sessionId ?? "", recordId ?? "");
                             if (pdfStream != null)
                             {
                                 await UploadAndSendPdfAsync(userId, pdfStream, filename ?? $"OphthalmoGuide_{DateTime.Now:yyyyMMdd_HHmmss}.pdf");
                             }
                            else
                            {
                                await SendAsync(userId, "❌ Не удалось сформировать отчёт.");
                            }
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "[VK] Payload parse error");
                    }
                }

                // 2. Начать /start (всегда показывает дисклеймер)
                if (text.Equals("начать", StringComparison.OrdinalIgnoreCase) ||
                    text.Equals("/start", StringComparison.OrdinalIgnoreCase))
                {
                    if (state == "active")
                    {
                        await RestartSessionAsync(userId, db, stKey, sesKey);
                        return;
                    }

                    await db.StringSetAsync(stKey, "disclaimer");
                    var kb = new KeyboardBuilder().SetOneTime()
                        .AddButton(new MessageKeyboardButtonAction
                        {
                            Type = KeyboardButtonActionType.Text,
                            Label = "✅ Согласен",
                            Payload = JsonSerializer.Serialize(new { button = "agree" })
                        }, KeyboardButtonColor.Positive)
                        .AddButton(new MessageKeyboardButtonAction
                        {
                            Type = KeyboardButtonActionType.Text,
                            Label = "❌ Не согласен",
                            Payload = JsonSerializer.Serialize(new { button = "disagree" })
                        }, KeyboardButtonColor.Negative)
                        .Build();
                    await SendAsync(userId, DisclaimerText, kb);
                    return;
                }

                // 3. Сброс (всегда доступен)
                if (text.Equals("начать заново", StringComparison.OrdinalIgnoreCase) ||
                    text.Equals("🔄 начать заново", StringComparison.OrdinalIgnoreCase) ||
                    text.Equals("/reset", StringComparison.OrdinalIgnoreCase))
                {
                    if (state != "active" && state != "results")
                    {
                        await SendAsync(userId, "Для начала работы примите дисклеймер – напишите \"Начать\".");
                        return;
                    }
                    await RestartSessionAsync(userId, db, stKey, sesKey);
                    return;
                }

                if (state == "results")
                {
                    await RestartSessionAsync(userId, db, stKey, sesKey);
                    return;
                }

                // 4. Дисклеймер не принят (или первое обращение)
                if (state != "active")
                {
                    await SendAsync(userId, "Для начала работы примите дисклеймер – напишите \"Начать\".");
                    return;
                }

                // Голосовое сообщение
                var isVoice = false;
                var voiceAtt = msg.Attachments?.FirstOrDefault(a => a.Instance is AudioMessage);
                if (voiceAtt?.Instance is AudioMessage am && am.LinkMp3 != null)
                {
                    isVoice = true;
                    await SendAsync(userId, "🎙️ Распознаю речь…");
                    text = await RecognizeSpeechAsync(am.LinkMp3.ToString(), ct) ?? "";
                    if (string.IsNullOrWhiteSpace(text))
                    {
                        await SendAsync(userId, "❌ Не удалось распознать речь. Попробуйте ещё раз или опишите жалобы текстом.");
                        return;
                    }
                    await SendAsync(userId, $"📝 Распознано:\n\"{text}\"");
                }

                if (string.IsNullOrWhiteSpace(text)) return;

                text = text.Trim();
                if (text.Length < 15)
                {
                    await SendAsync(userId, "Опишите ощущения подробнее – так диагностика будет точнее");
                    await SendAsync(userId, "Расскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.");
                    return;
                }

                // Анализ
                var sid = (string?)await db.StringGetAsync(sesKey);
                if (string.IsNullOrEmpty(sid))
                    sid = await NewSession(db, stKey, sesKey, userId);

                await SendAsync(userId, "🤖 Анализирую симптомы…");
                await AnalyzeAndReplyAsync(userId, sid, text, isVoice, ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[VK] Exception in OnMessageAsync for user {UserId}", userId);
                try
                {
                    await SendAsync(userId, "⚠️ Произошла непредвиденная ошибка при обработке сообщения.");
                    await SendAsync(userId, "Расскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.", ClearKeyboard());
                }
                catch (Exception vkEx)
                {
                    _logger.LogError(vkEx, "[VK] Failed to send error message to user");
                }
            }
        }

        private async Task<string?> RecognizeSpeechAsync(string url, CancellationToken ct)
        {
            try
            {
                var http = _httpClientFactory.CreateClient();
                var audio = await http.GetByteArrayAsync(url, ct);

                var content = new ByteArrayContent(audio);
                content.Headers.ContentType = MediaTypeHeaderValue.Parse("audio/mpeg");

                var resp = await http.PostAsync($"{_backendUrl}/speech/recognize", content, ct);
                if (!resp.IsSuccessStatusCode) return null;

                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
                return doc.RootElement.TryGetProperty("text", out var t) ? t.GetString() : null;
            }
            catch (Exception ex) { _logger.LogError(ex, "[VK] STT error"); return null; }
        }

        private static string GetThreatLabel(int level)
        {
            return level switch
            {
                0 => "Нет угрозы",
                1 => "Низкий",
                2 => "Средний",
                3 => "Критический",
                _ => "Неопределен"
            };
        }

        private static string GetThreatAdvice(int level)
        {
            return level switch
            {
                0 => "Здоровье ваших глаз в пределах нормы. Рекомендуется проходить профилактический осмотр у офтальмолога раз в год, защищать глаза от УФ-излучения качественными солнцезащитными очками и делать регулярные перерывы при работе за компьютером. При появлении новых симптомов повторно обратитесь к системе или врачу.",
                1 => "Выявленные симптомы могут указывать на легкие рефракционные нарушения или усталость глаз. Рекомендуется запланировать плановый визит к офтальмологу в течение ближайших недель для проверки остроты зрения и подбора коррекции. Регулярно делайте гимнастику для глаз и минимизируйте зрительное перенапряжение.",
                2 => "Симптомы указывают на возможное развитие воспалительного или хронического заболевания глаз. Рекомендуется обратиться к офтальмологу в ближайшие 2-3 дня для очной консультации и точной диагностики. Воздержитесь от ношения контактных линз, не трите глаза руками и не используйте глазные капли без назначения врача.",
                3 => "Данное состояние представляет непосредственную угрозу для зрения и требует экстренной медицинской помощи. Срочно, в течение суток, обратитесь в ближайший пункт неотложной офтальмологической помощи или вызовите скорую помощь. Не пытайтесь самостоятельно промывать или лечить глаз, обеспечьте ему максимальный покой.",
                _ => ""
            };
        }

        private async Task<bool> AnalyzeAndReplyAsync(long userId, string sessionId, string text, bool isVoice, CancellationToken ct)
        {
            try
            {
                var http = _httpClientFactory.CreateClient();
                http.DefaultRequestHeaders.Add("Session-Id", sessionId);

                var resp = await http.PostAsJsonAsync($"{_backendUrl}/analyze", new { Text = text }, ct);
                if (!resp.IsSuccessStatusCode)
                {
                    await SendAsync(userId, "❌ Сервер диагностики недоступен.");
                    await SendAsync(userId, "Расскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.", ClearKeyboard());
                    return false;
                }

                var r = await resp.Content.ReadFromJsonAsync<AnalyzeDto>(JsonOpts, ct);
                if (r == null || !r.Success)
                {
                    await SendAsync(userId, $"❌ {r?.Error ?? "Неизвестная ошибка"}");
                    await SendAsync(userId, "Расскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.", ClearKeyboard());
                    return false;
                }

                var sb = new StringBuilder("🔍 Заключение предварительного разбора\n\n");

                if (r.ExtractedSymptoms?.Count > 0)
                {
                    sb.AppendLine("📌 Выделенные клинические симптомы:");
                    foreach (var s in r.ExtractedSymptoms) sb.AppendLine($"  • {s}");
                    sb.AppendLine();
                }
                if (r.AssumedSymptoms?.Count > 0)
                {
                    sb.AppendLine("💡 Косвенные клинические симптомы:");
                    foreach (var s in r.AssumedSymptoms) sb.AppendLine($"  • {s}");
                    sb.AppendLine();
                }

                var sortedResults = r.Results?
                    .Where(x => x.MatchPercentage > 0)
                    .OrderByDescending(x => x.MatchPercentage)
                    .ToList() ?? new System.Collections.Generic.List<DiseaseMatchDto>();

                var displayedResults = sortedResults.Take(5).ToList();
                int maxThreatLevel = displayedResults.Count > 0 ? displayedResults.Max(x => x.ThreatLevel) : 0;

                if (displayedResults.Count > 0)
                {
                    sb.AppendLine("📋 Предполагаемые причины");
                    var topMatch = displayedResults[0];
                    int n = 1;
                    foreach (var m in displayedResults)
                    {
                        double relConf = Math.Round((m.MatchPercentage / topMatch.MatchPercentage) * 100);
                        double diffWeight = relConf / 100.0;
                        string threatLabel = GetThreatLabel(m.ThreatLevel);

                        sb.AppendLine($"{n}. {m.Disease}");
                        sb.AppendLine($"Уровень угрозы: {threatLabel}");
                        sb.AppendLine($"Дифференциальный вес: {diffWeight:F2}");
                        if (m.MatchingSymptomsCount > 0)
                        {
                            sb.AppendLine($"Совпадение по симптомам: {m.MatchPercentage:F1}% ({m.MatchingSymptomsCount} из {m.TotalDiseaseSymptomsCount} симптомов)");
                        }
                        if (m.MatchedSymptoms?.Count > 0)
                        {
                            sb.AppendLine($"Симптомы: {string.Join(", ", m.MatchedSymptoms)}");
                        }
                        n++;
                    }
                }
                else
                {
                    sb.AppendLine("🟢 Заболеваний не выявлено.");
                }

                sb.AppendLine();
                sb.AppendLine("💬 Рекомендации и дальнейшие действия:");
                sb.AppendLine(GetThreatAdvice(maxThreatLevel));

                if (maxThreatLevel == 3)
                {
                    sb.AppendLine();
                    sb.AppendLine("📞 Экстренные службы:");
                    sb.AppendLine("• 112 – единый номер вызова экстренных оперативных служб");
                    sb.AppendLine("• 103 – общефедеральный номер вызова скорой медицинской помощи");
                }

                MessageKeyboard? kb = null;
                var builder = new KeyboardBuilder().SetInline(true);
                bool hasButtons = false;

                if (!string.IsNullOrEmpty(r.HistoryRecordId))
                {
                    builder.AddButton(new MessageKeyboardButtonAction
                    {
                        Type = KeyboardButtonActionType.Text,
                        Label = "📥 Скачать отчёт",
                        Payload = JsonSerializer.Serialize(new { cmd = "pdf", id = r.HistoryRecordId })
                    }, KeyboardButtonColor.Primary);
                    hasButtons = true;
                }

                if (maxThreatLevel == 3)
                {
                    if (hasButtons) builder.AddLine();
                    builder.AddButton(new MessageKeyboardButtonAction
                    {
                        Type = KeyboardButtonActionType.OpenLink,
                        Link = new Uri("https://yandex.ru/maps/?text=%D0%A6%D0%B5%D0%BD%D1%82%D1%80%20%D0%BD%D0%B5%D0%BE%D1%82%D0%BB%D0%BE%D0%B6%D0%BD%D0%BE%D0%B9%20%D0%BE%D1%84%D1%82%D0%B0%D0%BB%D1%8C%D0%BC%D0%BE%D0%BB%D0%BE%D0%B3%D0%B8%D1%87%D0%B5%D1%81%D0%BA%D0%BE%D0%B9%20%D0%BF%D0%BE%D0%BC%D0%BE%D1%89%D0%B8"),
                        Label = "📍 Найти пункт неотложной помощи на карте"
                    }, null);
                    hasButtons = true;
                }

                if (hasButtons)
                {
                    kb = builder.Build();
                }

                if (isVoice)
                {
                    string ttsText = BuildTtsSpeechText(displayedResults, maxThreatLevel);

                    var audioBytes = await SynthesizeSpeechAsync(ttsText, ct);
                    if (audioBytes != null)
                    {
                        await UploadAndSendVoiceAsync(userId, audioBytes, null, ct);
                    }
                }

                if (hasButtons)
                {
                    await SendAsync(userId, sb.ToString(), kb);
                    await SendAsync(userId, "Для начала новой диагностики нажмите кнопку ниже:", MainKeyboard());
                }
                else
                {
                    await SendAsync(userId, sb.ToString(), MainKeyboard());
                }

                var db = _redis.GetDatabase();
                var stKey = $"bot:vk:state:{userId}";
                await db.StringSetAsync(stKey, "results");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[VK] Analyze error");
                await SendAsync(userId, "❌ Ошибка при анализе.");
                await SendAsync(userId, "Расскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.", ClearKeyboard());
                return false;
            }
        }

        private async Task<(Stream? Stream, string? Filename)> DownloadPdfAsync(string sessionId, string recordId)
        {
            try
            {
                var http = _httpClientFactory.CreateClient();
                http.DefaultRequestHeaders.Add("Session-Id", sessionId);
                var resp = await http.GetAsync($"{_backendUrl}/report/pdf?id={recordId}");
                if (!resp.IsSuccessStatusCode) return (null, null);

                var stream = await resp.Content.ReadAsStreamAsync();
                var filename = resp.Content.Headers.ContentDisposition?.FileName?.Trim('"') 
                            ?? resp.Content.Headers.ContentDisposition?.FileNameStar?.Trim('"');

                return (stream, filename);
            }
            catch (Exception ex) { _logger.LogError(ex, "[VK] PDF download error"); return (null, null); }
        }

        private async Task UploadAndSendPdfAsync(long userId, Stream pdfStream, string filename)
        {
            try
            {
                var uploadServer = await _vk!.Docs.GetMessagesUploadServerAsync(userId, DocMessageType.Doc);
                var http = _httpClientFactory.CreateClient();

                using var content = new MultipartFormDataContent();
                var streamContent = new StreamContent(pdfStream);
                streamContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/pdf");
                content.Add(streamContent, "file", filename);

                var uploadResp = await http.PostAsync(uploadServer.UploadUrl, content);
                if (!uploadResp.IsSuccessStatusCode)
                {
                    await SendAsync(userId, "❌ Не удалось загрузить PDF в ВК.");
                    return;
                }

                var json = await uploadResp.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);

                if (doc.RootElement.TryGetProperty("file", out var fileProp))
                {
                    var saved = await _vk.Docs.SaveAsync(fileProp.GetString(), filename);
                    if (saved?.Count > 0)
                    {
                        await _vk.Messages.SendAsync(new MessagesSendParams
                        {
                            RandomId = new Random().Next(),
                            UserId = userId,
                            Attachments = new[] { saved[0].Instance }
                        });
                        return;
                    }
                }

                await SendAsync(userId, "❌ Не удалось отправить PDF.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[VK] PDF upload error");
                await SendAsync(userId, "❌ Ошибка при отправке PDF.");
            }
        }

        // ──────────── Утилиты ────────────

        private static async Task<string> NewSession(IDatabase db, string stKey, string sesKey, long userId)
        {
            var sid = (string?)await db.StringGetAsync(sesKey);
            if (string.IsNullOrEmpty(sid))
            {
                var userGuid = Guid.NewGuid();
                sid = $"sess_{userGuid}_vk_{userId}";
                await db.StringSetAsync(sesKey, sid);
            }

            await db.StringSetAsync(stKey, "active");
            return sid;
        }

        private MessageKeyboard MainKeyboard() =>
            new KeyboardBuilder()
                .AddButton(new MessageKeyboardButtonAction
                {
                    Type = KeyboardButtonActionType.Text,
                    Label = "🔄 Начать заново",
                    Payload = JsonSerializer.Serialize(new { button = "restart" })
                }, KeyboardButtonColor.Primary)
                .Build();

        private async Task<bool> ProcessRateLimitAsync(long userId, Message msg, CancellationToken ct)
        {
            if (!string.IsNullOrEmpty(msg.Payload))
            {
                try
                {
                    using var doc = JsonDocument.Parse(msg.Payload);
                    if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                        doc.RootElement.TryGetProperty("ratelimit_emoji", out var emojiProp))
                    {
                        var clickedEmoji = emojiProp.GetString();
                        var expectedEmoji = await _rateLimiter.GetExpectedEmojiAsync("vk", userId);

                        if (clickedEmoji == expectedEmoji)
                        {
                            await _rateLimiter.UnblockAsync("vk", userId);
                            await SendAsync(userId, "✅ Проверка пройдена! Блокировка снята. Вы можете продолжить пользоваться ботом.", ClearKeyboard());
                        }
                        else
                        {
                            var challenge = await _rateLimiter.GenerateChallengeAsync("vk", userId);
                            var kbBuilder = new KeyboardBuilder();
                            foreach (var opt in challenge.Options)
                            {
                                kbBuilder.AddButton(new MessageKeyboardButtonAction
                                {
                                    Type = KeyboardButtonActionType.Text,
                                    Label = opt,
                                    Payload = JsonSerializer.Serialize(new { ratelimit_emoji = opt })
                                }, KeyboardButtonColor.Default);
                            }
                            await SendAsync(userId, $"❌ Неверно! Попробуйте еще раз.\n\n⚠️ Вы отправляете сообщения слишком часто! Для продолжения подтвердите, что вы человек.\nНажмите на кнопку с эмодзи: {challenge.TargetName}", kbBuilder.Build());
                        }
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[VK] Failed to parse VK rate limit payload");
                }
            }

            bool isBlocked = await _rateLimiter.IsBlockedAsync("vk", userId);
            if (isBlocked)
            {
                await SendAsync(userId, "⚠️ Вы временно заблокированы за слишком частые сообщения. Пожалуйста, пройдите проверку выше, выбрав правильный эмодзи на клавиатуре.");
                return true;
            }

            if (string.IsNullOrEmpty(msg.Payload))
            {
                bool limitExceeded = await _rateLimiter.IncrementAndCheckLimitAsync("vk", userId);
                if (limitExceeded)
                {
                    var challenge = await _rateLimiter.GenerateChallengeAsync("vk", userId);
                    var kbBuilder = new KeyboardBuilder();
                    foreach (var opt in challenge.Options)
                    {
                        kbBuilder.AddButton(new MessageKeyboardButtonAction
                        {
                            Type = KeyboardButtonActionType.Text,
                            Label = opt,
                            Payload = JsonSerializer.Serialize(new { ratelimit_emoji = opt })
                        }, KeyboardButtonColor.Default);
                    }
                    await SendAsync(userId, $"⚠️ Вы отправляете сообщения слишком часто! Для продолжения подтвердите, что вы человек.\n\nНажмите на кнопку с эмодзи: {challenge.TargetName}", kbBuilder.Build());
                    return true;
                }
            }

            return false;
        }

        private MessageKeyboard ClearKeyboard() =>
            new KeyboardBuilder().Build();

        private async Task RestartSessionAsync(long userId, IDatabase db, string stKey, string sesKey)
        {
            await NewSession(db, stKey, sesKey, userId);
            await SendAsync(userId, "Расскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.", ClearKeyboard());
        }

        private async Task SendAsync(long userId, string text, MessageKeyboard? keyboard = null)
        {
            await _vk!.Messages.SendAsync(new MessagesSendParams
            {
                RandomId = new Random().Next(),
                UserId = userId,
                Message = text,
                Keyboard = keyboard
            });
        }

        // ──────────── DTO ────────────

        private sealed class AnalyzeDto
        {
            public bool Success { get; set; }
            public string? Error { get; set; }
            public string? HistoryRecordId { get; set; }
            public System.Collections.Generic.List<string>? ExtractedSymptoms { get; set; }
            public System.Collections.Generic.List<string>? AssumedSymptoms { get; set; }
            public System.Collections.Generic.List<DiseaseMatchDto>? Results { get; set; }
        }

        private sealed class DiseaseMatchDto
        {
            public string Disease { get; set; } = "";
            public double MatchPercentage { get; set; }
            public System.Collections.Generic.List<string>? MatchedSymptoms { get; set; }
            public int ThreatLevel { get; set; }
            public int MatchingSymptomsCount { get; set; }
            public int TotalDiseaseSymptomsCount { get; set; }
        }

        private async Task<bool> UploadAndSendVoiceAsync(long userId, byte[] audioBytes, MessageKeyboard? kb, CancellationToken ct)
        {
            try
            {
                var parameters = new VkParameters
                {
                    { "type", "audio_message" },
                    { "peer_id", userId }
                };
                var uploadServer = await _vk!.CallAsync<UploadServerInfo>("docs.getMessagesUploadServer", parameters);
                var http = _httpClientFactory.CreateClient();

                using var content = new MultipartFormDataContent();
                var streamContent = new ByteArrayContent(audioBytes);
                streamContent.Headers.ContentType = MediaTypeHeaderValue.Parse("audio/ogg");
                content.Add(streamContent, "file", "speech.ogg");

                var uploadResp = await http.PostAsync(uploadServer.UploadUrl, content, ct);
                if (!uploadResp.IsSuccessStatusCode)
                {
                    _logger.LogWarning("[VK] Failed to upload audio bytes to VK upload server.");
                    return false;
                }

                var json = await uploadResp.Content.ReadAsStringAsync(ct);
                using var doc = JsonDocument.Parse(json);

                if (doc.RootElement.TryGetProperty("file", out var fileProp))
                {
                    var saved = await _vk.Docs.SaveAsync(fileProp.GetString(), "speech");
                    if (saved?.Count > 0)
                    {
                        await _vk.Messages.SendAsync(new MessagesSendParams
                        {
                            RandomId = new Random().Next(),
                            UserId = userId,
                            Attachments = new[] { saved[0].Instance },
                            Keyboard = kb
                        });
                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[VK] Voice upload error, falling back to text response");
                return false;
            }
        }

        private async Task<byte[]?> SynthesizeSpeechAsync(string text, CancellationToken ct)
        {
            try
            {
                var http = _httpClientFactory.CreateClient();
                var resp = await http.PostAsJsonAsync($"{_backendUrl}/speech/synthesize", new { text = text }, ct);
                if (resp.IsSuccessStatusCode)
                {
                    return await resp.Content.ReadAsByteArrayAsync(ct);
                }
                else
                {
                    var err = await resp.Content.ReadAsStringAsync(ct);
                    _logger.LogWarning("[VK-TTS] Synthesis failed: {StatusCode} - {Error}", resp.StatusCode, err);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[VK-TTS] Error calling synthesis API");
            }
            return null;
        }

        private static string BuildTtsSpeechText(System.Collections.Generic.List<DiseaseMatchDto> displayedResults, int maxThreatLevel)
        {
            if (displayedResults == null || displayedResults.Count == 0 || maxThreatLevel == 0)
            {
                return $"По результатам анализа заболеваний не выявлено. Рекомендация: {GetThreatAdvice(0)}";
            }

            var sb = new StringBuilder();
            for (int i = 0; i < displayedResults.Count; i++)
            {
                var d = displayedResults[i];
                string threatText = GetThreatLabel(d.ThreatLevel).ToLower();
                
                if (i == 0)
                {
                    sb.Append($"Наиболее вероятным заболеванием является {d.Disease}, уровень угрозы: {threatText}. ");
                }
                else if (i == 1)
                {
                    sb.Append($"Далее по степени вероятности следует {d.Disease}, уровень угрозы: {threatText}. ");
                }
                else if (i == 2)
                {
                    sb.Append($"Затем идет {d.Disease}, уровень угрозы: {threatText}. ");
                }
                else if (i == 3)
                {
                    sb.Append($"Следующее возможное заболевание – {d.Disease}, уровень угрозы: {threatText}. ");
                }
                else if (i == 4)
                {
                    sb.Append($"И на пятом месте – {d.Disease}, уровень угрозы: {threatText}. ");
                }
            }

            sb.Append($"Рекомендация: {GetThreatAdvice(maxThreatLevel)}");
            if (maxThreatLevel == 3)
            {
                sb.Append(" Вы можете вызвать экстренную помощь по номерам 112 или 103.");
            }
            return sb.ToString();
        }

        private static string CleanTextForSpeech(string text)
        {
            if (string.IsNullOrEmpty(text)) return "";

            var sb = new StringBuilder(text);
            sb.Replace("*", "");

            string[] emojis = { "🔍", "📌", "💡", "📋", "💬", "🟢", "❌", "📥", "📍", "🔄", "🎙️", "📝", "🤖", "📞", "⚠️", "•" };
            foreach (var emoji in emojis)
            {
                sb.Replace(emoji, "");
            }

            var cleaned = sb.ToString();
            cleaned = System.Text.RegularExpressions.Regex.Replace(cleaned, @"\[([^\]]+)\]\([^\)]+\)", "$1");
            cleaned = System.Text.RegularExpressions.Regex.Replace(cleaned, @"https?://[^\s]+", "");
            cleaned = System.Text.RegularExpressions.Regex.Replace(cleaned, @"\n+", "\n");
            cleaned = System.Text.RegularExpressions.Regex.Replace(cleaned, @" +", " ");

            return cleaned.Trim();
        }
    }
}
