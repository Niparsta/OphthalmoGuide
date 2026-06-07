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
using Telegram.Bot;
using Telegram.Bot.Exceptions;
using Telegram.Bot.Polling;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;
using Telegram.Bot.Types.ReplyMarkups;

namespace bot_workerservice.Services
{
    public class TelegramBotService : BackgroundService
    {
        private readonly ILogger<TelegramBotService> _logger;
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConnectionMultiplexer _redis;

        private TelegramBotClient? _botClient;
        private string _backendUrl = "http://localhost:5190";
        private HashSet<long> _allowedUserIds = new();
        private bool _restrictAccess;

        private const string DisclaimerText =
            "⚠️ *Дисклеймер*\n\n" +
            "Сервис носит исключительно информационно-справочный характер и не является медицинским изделием " +
            "или системой поддержки принятия врачебных решений. Представленные сведения не являются диагнозом, " +
            "назначением или руководством к самолечению и не заменяют очную консультацию квалифицированного врача. " +
            "Полнота и точность представленной информации не гарантируются; ответственность за её самостоятельную " +
            "интерпретацию и принятые на её основе решения несёт пользователь. При любых симптомах обратитесь " +
            "к врачу-специалисту, а в неотложных случаях – вызовите скорую медицинскую помощь (112/103)." +
            "\n\nВы согласны с условиями использования?";

        private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

        public TelegramBotService(
            ILogger<TelegramBotService> logger,
            IConfiguration configuration,
            IHttpClientFactory httpClientFactory,
            IConnectionMultiplexer redis)
        {
            _logger = logger;
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
            _redis = redis;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var token = _configuration["Telegram:Token"];
            if (string.IsNullOrWhiteSpace(token))
            {
                _logger.LogWarning("[TG] Telegram Bot Token is not configured. Service will not start.");
                return;
            }

            _backendUrl = (_configuration["Backend:Url"] ?? _backendUrl).TrimEnd('/');

            var ids = _configuration["Telegram:AllowedUserIds"];
            if (!string.IsNullOrWhiteSpace(ids))
            {
                _allowedUserIds = ids.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(long.Parse).ToHashSet();
                _restrictAccess = true;
                _logger.LogInformation("[TG] Access restricted to {Count} user(s).", _allowedUserIds.Count);
            }

            _botClient = new TelegramBotClient(token);
            var me = await _botClient.GetMeAsync(stoppingToken);
            _logger.LogInformation("[TG] Bot @{Username} started.", me.Username);

            _botClient.StartReceiving(
                updateHandler: HandleUpdateAsync,
                pollingErrorHandler: HandlePollingErrorAsync,
                receiverOptions: new ReceiverOptions { AllowedUpdates = Array.Empty<UpdateType>() },
                cancellationToken: stoppingToken);

            await Task.Delay(Timeout.Infinite, stoppingToken);
        }

        // ──────────── Маршрутизация обновлений ────────────

        private async Task HandleUpdateAsync(ITelegramBotClient bot, Update update, CancellationToken ct)
        {
            try
            {
                var userId = update.Message?.From?.Id ?? update.CallbackQuery?.From?.Id;
                if (userId == null) return;
                if (_restrictAccess && !_allowedUserIds.Contains(userId.Value)) return;

                if (update.CallbackQuery is { } cb) await OnCallbackAsync(bot, cb, ct);
                else if (update.Message is { } msg) await OnMessageAsync(bot, msg, ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[TG] Error handling update {Id}", update.Id);
            }
        }

        // ──────────── Сообщения ────────────

        private async Task OnMessageAsync(ITelegramBotClient bot, Message msg, CancellationToken ct)
        {
            var chatId = msg.Chat.Id;
            var userId = msg.From?.Id ?? chatId;
            try
            {
                var text   = msg.Text?.Trim();
                var db     = _redis.GetDatabase();
                var stKey  = $"bot:tg:state:{userId}";
                var sesKey = $"bot:tg:session:{userId}";
                var state  = (string?)await db.StringGetAsync(stKey);

                // 1. /start — показ дисклеймера
                if (text == "/start")
                {
                    if (state == "active")
                    {
                        await RestartSessionAsync(bot, chatId, db, stKey, sesKey, userId, ct);
                        return;
                    }

                    await db.StringSetAsync(stKey, "disclaimer");
                    await bot.SendTextMessageAsync(chatId, DisclaimerText, parseMode: ParseMode.Markdown,
                        replyMarkup: new ReplyKeyboardMarkup(new[]
                        {
                            new KeyboardButton[] { "✅ Согласен", "❌ Не согласен" }
                        }) { ResizeKeyboard = true, OneTimeKeyboard = true }, cancellationToken: ct);
                    return;
                }

                // 2. Сброс (всегда доступен)
                if (text == "/reset" || 
                    text?.Equals("начать заново", StringComparison.OrdinalIgnoreCase) == true || 
                    text?.Equals("🔄 начать заново", StringComparison.OrdinalIgnoreCase) == true)
                {
                    await RestartSessionAsync(bot, chatId, db, stKey, sesKey, userId, ct);
                    return;
                }

                // Обработка ответов согласия/несогласия
                if (text == "✅ Согласен")
                {
                    await NewSession(db, stKey, sesKey, userId);
                    await bot.SendTextMessageAsync(chatId,
                        "✅ Спасибо!\n\nРасскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.",
                        replyMarkup: new ReplyKeyboardRemove(), cancellationToken: ct);
                    return;
                }

                if (text == "❌ Не согласен")
                {
                    await bot.SendTextMessageAsync(chatId,
                        "❌ Без согласия диагностика невозможна. Отправьте /start, чтобы вернуться к соглашению.",
                        replyMarkup: new ReplyKeyboardRemove(), cancellationToken: ct);
                    return;
                }

                if (text == "📥 Скачать отчёт")
                {
                    var lastPdfKey = $"bot:tg:last_pdf:{userId}";
                    var recordId = (string?)await db.StringGetAsync(lastPdfKey);
                    if (!string.IsNullOrEmpty(recordId))
                    {
                        var sessionId2 = (string?)await db.StringGetAsync(sesKey);
                        await bot.SendTextMessageAsync(chatId, "📥 Формирую отчёт…", cancellationToken: ct);
                        var (pdf, filename) = await DownloadPdfAsync(sessionId2 ?? "", recordId);
                        if (pdf != null)
                        {
                            var name = filename ?? $"OphthalmoGuide_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
                            await bot.SendDocumentAsync(chatId, InputFile.FromStream(pdf, name), cancellationToken: ct);
                        }
                        else
                        {
                            await bot.SendTextMessageAsync(chatId, "❌ Не удалось сформировать отчёт.", cancellationToken: ct);
                        }
                    }
                    else
                    {
                        await bot.SendTextMessageAsync(chatId, "❌ Отчёт не найден или устарел.", cancellationToken: ct);
                    }
                    return;
                }

                if (state == "results")
                {
                    await RestartSessionAsync(bot, chatId, db, stKey, sesKey, userId, ct);
                    return;
                }

                // 3. Дисклеймер не принят (или первое обращение)
                if (state != "active")
                {
                    await bot.SendTextMessageAsync(chatId,
                        "Для начала работы примите дисклеймер — отправьте /start",
                        cancellationToken: ct);
                    return;
                }

                // Голосовое сообщение → STT → текст
                var isVoice = false;
                if (msg.Voice != null || msg.Audio != null)
                {
                    var fileId = msg.Voice?.FileId ?? msg.Audio?.FileId;
                    if (fileId == null) return;

                    isVoice = true;
                    await bot.SendTextMessageAsync(chatId, "🎙️ Распознаю речь…", cancellationToken: ct);
                    text = await RecognizeSpeechAsync(bot, fileId, ct);
                    if (string.IsNullOrWhiteSpace(text))
                    {
                        await bot.SendTextMessageAsync(chatId,
                            "❌ Не удалось распознать речь. Попробуйте ещё раз или отправьте текстом.",
                            cancellationToken: ct);
                        return;
                    }
                    await bot.SendTextMessageAsync(chatId, $"📝 Распознано:\n\"{text}\"",
                        cancellationToken: ct);
                }

                if (string.IsNullOrWhiteSpace(text)) return;

                text = text.Trim();
                if (text.Length < 15)
                {
                    await bot.SendTextMessageAsync(chatId,
                        "Опишите ощущения подробнее – так диагностика будет точнее",
                        cancellationToken: ct);
                    await bot.SendTextMessageAsync(chatId,
                        "Расскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.",
                        cancellationToken: ct);
                    return;
                }

                // Анализ жалобы
                var sessionId = (string?)await db.StringGetAsync(sesKey);
                if (string.IsNullOrEmpty(sessionId))
                    sessionId = await NewSession(db, stKey, sesKey, userId);

                await bot.SendTextMessageAsync(chatId, "🤖 Анализирую симптомы…", cancellationToken: ct);
                await AnalyzeAndReplyAsync(bot, chatId, sessionId, text, isVoice, userId, ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[TG] Exception in OnMessageAsync for user {UserId}", userId);
                try
                {
                    await bot.SendTextMessageAsync(chatId,
                        "⚠️ Произошла непредвиденная ошибка при обработке сообщения.", cancellationToken: ct);
                    await bot.SendTextMessageAsync(chatId,
                        "Расскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.",
                        replyMarkup: new ReplyKeyboardRemove(), cancellationToken: ct);
                }
                catch (Exception tgEx)
                {
                    _logger.LogError(tgEx, "[TG] Failed to send error message to user");
                }
            }
        }

        // ──────────── Callback-кнопки ────────────

        private async Task OnCallbackAsync(ITelegramBotClient bot, CallbackQuery cb, CancellationToken ct)
        {
            var chatId = cb.Message?.Chat.Id;
            if (chatId == null) return;
            var userId = cb.From.Id;
            var db     = _redis.GetDatabase();
            var stKey  = $"bot:tg:state:{userId}";
            var sesKey = $"bot:tg:session:{userId}";

            switch (cb.Data)
            {
                case "agree":
                    await NewSession(db, stKey, sesKey, userId);
                    await bot.AnswerCallbackQueryAsync(cb.Id, "Принято", cancellationToken: ct);
                    await bot.SendTextMessageAsync(chatId.Value,
                        "✅ Спасибо!\n\nРасскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.",
                        replyMarkup: new ReplyKeyboardRemove(), cancellationToken: ct);
                    break;

                case "disagree":
                    await bot.AnswerCallbackQueryAsync(cb.Id, cancellationToken: ct);
                    await bot.SendTextMessageAsync(chatId.Value,
                        "❌ Без согласия диагностика невозможна. Отправьте /start, чтобы вернуться к соглашению.",
                        cancellationToken: ct);
                    break;

                case "restart":
                case "clear":
                case "reset":
                    await bot.AnswerCallbackQueryAsync(cb.Id, "Перезапущено", cancellationToken: ct);
                    await RestartSessionAsync(bot, chatId.Value, db, stKey, sesKey, userId, ct);
                    break;

                default:
                    if (cb.Data?.StartsWith("pdf:") == true)
                    {
                        var recordId  = cb.Data[4..];
                        var sessionId = (string?)await db.StringGetAsync(sesKey);
                        await bot.AnswerCallbackQueryAsync(cb.Id, "Формирую отчёт…", cancellationToken: ct);

                        var (pdf, filename) = await DownloadPdfAsync(sessionId ?? "", recordId);
                        if (pdf != null)
                        {
                            var name = filename ?? $"OphthalmoGuide_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
                            await bot.SendDocumentAsync(chatId.Value,
                                InputFile.FromStream(pdf, name),
                                cancellationToken: ct);
                        }
                        else
                        {
                            await bot.SendTextMessageAsync(chatId.Value,
                                "❌ Не удалось сформировать отчёт.",
                                replyMarkup: new InlineKeyboardMarkup(new[]
                                {
                                    InlineKeyboardButton.WithCallbackData("🔄 Начать заново", "restart")
                                }), cancellationToken: ct);
                        }
                    }
                    break;
            }
        }

        // ──────────── Вызов Backend API ────────────

        private async Task<string?> RecognizeSpeechAsync(ITelegramBotClient bot, string fileId, CancellationToken ct)
        {
            try
            {
                var file = await bot.GetFileAsync(fileId, ct);
                if (file.FilePath == null) return null;

                using var ms = new MemoryStream();
                await bot.DownloadFileAsync(file.FilePath, ms, ct);

                var http    = _httpClientFactory.CreateClient();
                var content = new ByteArrayContent(ms.ToArray());
                content.Headers.ContentType = MediaTypeHeaderValue.Parse("audio/ogg;codecs=opus");

                var resp = await http.PostAsync($"{_backendUrl}/api/speech/recognize", content, ct);
                if (!resp.IsSuccessStatusCode) return null;

                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
                return doc.RootElement.TryGetProperty("text", out var t) ? t.GetString() : null;
            }
            catch (Exception ex) { _logger.LogError(ex, "[TG] STT error"); return null; }
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

        private async Task<bool> AnalyzeAndReplyAsync(ITelegramBotClient bot, long chatId,
            string sessionId, string text, bool isVoice, long userId, CancellationToken ct)
        {
            try
            {
                var db   = _redis.GetDatabase();
                var http = _httpClientFactory.CreateClient();
                http.DefaultRequestHeaders.Add("Session-Id", sessionId);

                var resp = await http.PostAsJsonAsync($"{_backendUrl}/api/analyze", new { Text = text }, ct);
                if (!resp.IsSuccessStatusCode)
                {
                    await bot.SendTextMessageAsync(chatId, "❌ Сервер диагностики недоступен.", cancellationToken: ct);
                    await bot.SendTextMessageAsync(chatId,
                        "Расскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.",
                        replyMarkup: new ReplyKeyboardRemove(), cancellationToken: ct);
                    return false;
                }

                var r = await resp.Content.ReadFromJsonAsync<AnalyzeDto>(JsonOpts, ct);
                if (r == null || !r.Success)
                {
                    await bot.SendTextMessageAsync(chatId,
                        $"❌ {r?.Error ?? "Неизвестная ошибка"}", cancellationToken: ct);
                    await bot.SendTextMessageAsync(chatId,
                        "Расскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.",
                        replyMarkup: new ReplyKeyboardRemove(), cancellationToken: ct);
                    return false;
                }



                var sb = new StringBuilder("🔍 *Заключение предварительного разбора*\n\n");

                if (r.ExtractedSymptoms?.Count > 0)
                {
                    sb.AppendLine("📌 *Выделенные клинические симптомы:*");
                    foreach (var s in r.ExtractedSymptoms) sb.AppendLine($"  • {s}");
                    sb.AppendLine();
                }
                if (r.AssumedSymptoms?.Count > 0)
                {
                    sb.AppendLine("💡 *Косвенные клинические симптомы:*");
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
                    sb.AppendLine("📋 *Предполагаемые причины*");
                    var topMatch = displayedResults[0];
                    int n = 1;
                    foreach (var m in displayedResults)
                    {
                        double relConf = Math.Round((m.MatchPercentage / topMatch.MatchPercentage) * 100);
                        double diffWeight = relConf / 100.0;
                        string threatLabel = GetThreatLabel(m.ThreatLevel);

                        sb.AppendLine($"{n}. *{m.Disease}*");
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
                sb.AppendLine("💬 *Рекомендации и дальнейшие действия:*");
                sb.AppendLine(GetThreatAdvice(maxThreatLevel));

                if (maxThreatLevel == 3)
                {
                    sb.AppendLine();
                    sb.AppendLine("📞 *Экстренные службы:*");
                    sb.AppendLine("• 112 – единый номер вызова экстренных оперативных служб");
                    sb.AppendLine("• 103 – общефедеральный номер вызова скорой медицинской помощи");
                }

                InlineKeyboardMarkup? kb = null;
                var buttons = new System.Collections.Generic.List<InlineKeyboardButton[]>();
                if (!string.IsNullOrEmpty(r.HistoryRecordId))
                {
                    buttons.Add(new[] { InlineKeyboardButton.WithCallbackData("📥 Скачать отчёт", $"pdf:{r.HistoryRecordId}") });
                }
                if (maxThreatLevel == 3)
                {
                    buttons.Add(new[] { InlineKeyboardButton.WithUrl("📍 Найти пункт неотложной помощи на карте", "https://yandex.ru/maps/?text=%D0%A6%D0%B5%D0%BD%D1%82%D1%80%20%D0%BD%D0%B5%D0%BE%D1%82%D0%BB%D0%BE%D0%B6%D0%BD%D0%BE%D0%B9%20%D0%BE%D1%84%D1%82%D0%B0%D0%BB%D1%8C%D0%BC%D0%BE%D0%BB%D0%BE%D0%B3%D0%B8%D1%87%D0%B5%D1%81%D0%BA%D0%BE%D0%B9%20%D0%BF%D0%BE%D0%BC%D0%BE%D1%89%D0%B8") });
                }
                if (buttons.Count > 0)
                {
                    kb = new InlineKeyboardMarkup(buttons);
                }

                if (isVoice)
                {
                    string ttsText = BuildTtsSpeechText(displayedResults, maxThreatLevel);

                    var audioBytes = await SynthesizeSpeechAsync(ttsText, ct);
                    if (audioBytes != null)
                    {
                        try
                        {
                            using var ms = new MemoryStream(audioBytes);
                            await bot.SendVoiceAsync(
                                chatId: chatId,
                                voice: InputFile.FromStream(ms, "speech.ogg"),
                                cancellationToken: ct
                            );
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "[TG] Failed to send voice message");
                        }
                    }
                }

                await bot.SendTextMessageAsync(chatId, sb.ToString(),
                    parseMode: ParseMode.Markdown, replyMarkup: kb, cancellationToken: ct);

                await bot.SendTextMessageAsync(chatId, "Для начала новой диагностики нажмите кнопку ниже:",
                    replyMarkup: new ReplyKeyboardMarkup(new[]
                    {
                        new KeyboardButton[] { "🔄 Начать заново" }
                    }) { ResizeKeyboard = true }, cancellationToken: ct);

                var stKey = $"bot:tg:state:{userId}";
                await db.StringSetAsync(stKey, "results");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[TG] Analyze error");
                await bot.SendTextMessageAsync(chatId, "❌ Произошла ошибка при анализе симптомов.", cancellationToken: ct);
                await bot.SendTextMessageAsync(chatId,
                    "Расскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.",
                    replyMarkup: new ReplyKeyboardRemove(), cancellationToken: ct);
                return false;
            }
        }

        private async Task<(Stream? Stream, string? Filename)> DownloadPdfAsync(string sessionId, string recordId)
        {
            try
            {
                var http = _httpClientFactory.CreateClient();
                http.DefaultRequestHeaders.Add("Session-Id", sessionId);
                var resp = await http.GetAsync($"{_backendUrl}/api/report/pdf?id={recordId}");
                if (!resp.IsSuccessStatusCode) return (null, null);

                var stream = await resp.Content.ReadAsStreamAsync();
                var filename = resp.Content.Headers.ContentDisposition?.FileName?.Trim('"') 
                            ?? resp.Content.Headers.ContentDisposition?.FileNameStar?.Trim('"');

                return (stream, filename);
            }
            catch (Exception ex) { _logger.LogError(ex, "[TG] PDF download error"); return (null, null); }
        }

        // ──────────── Утилиты ────────────

        private static async Task<string> NewSession(IDatabase db, string stKey, string sesKey, long userId)
        {
            var sid = (string?)await db.StringGetAsync(sesKey);
            if (string.IsNullOrEmpty(sid))
            {
                var userGuid = Guid.NewGuid();
                sid = $"sess_{userGuid}_tg_{userId}";
                await db.StringSetAsync(sesKey, sid);
            }

            await db.StringSetAsync(stKey, "active");
            return sid;
        }

        private async Task RestartSessionAsync(ITelegramBotClient bot, long chatId, IDatabase db, string stKey, string sesKey, long userId, CancellationToken ct)
        {
            await NewSession(db, stKey, sesKey, userId);
            await bot.SendTextMessageAsync(chatId,
                "Расскажите, что Вы чувствуете? Опишите жалобы текстом или голосовым сообщением.",
                replyMarkup: new ReplyKeyboardRemove(), cancellationToken: ct);
        }

        private Task HandlePollingErrorAsync(ITelegramBotClient bot, Exception ex, CancellationToken ct)
        {
            _logger.LogError(ex, "[TG] Polling error");
            return Task.CompletedTask;
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
        private async Task<byte[]?> SynthesizeSpeechAsync(string text, CancellationToken ct)
        {
            try
            {
                var http = _httpClientFactory.CreateClient();
                var resp = await http.PostAsJsonAsync($"{_backendUrl}/api/speech/synthesize", new { text = text }, ct);
                if (resp.IsSuccessStatusCode)
                {
                    return await resp.Content.ReadAsByteArrayAsync(ct);
                }
                else
                {
                    var err = await resp.Content.ReadAsStringAsync(ct);
                    _logger.LogWarning("[TG-TTS] Synthesis failed: {StatusCode} - {Error}", resp.StatusCode, err);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[TG-TTS] Error calling synthesis API");
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
                    sb.Append($"Следующее возможное заболевание — {d.Disease}, уровень угрозы: {threatText}. ");
                }
                else if (i == 4)
                {
                    sb.Append($"И на пятом месте — {d.Disease}, уровень угрозы: {threatText}. ");
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
