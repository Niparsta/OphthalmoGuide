using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using StackExchange.Redis;

namespace bot_workerservice.Services
{
    public class BotRateLimiter
    {
        private readonly IConnectionMultiplexer _redis;
        private const int MaxMessages = 10;
        private const int WindowSeconds = 10;
        private const int BlockExpiryMinutes = 5;

        public static readonly Dictionary<string, string> EmojiPool = new()
        {
            { "🍎", "Яблоко" },
            { "🚗", "Машина" },
            { "🐱", "Кот" },
            { "🔑", "Ключ" },
            { "🐶", "Собака" },
            { "🦊", "Лиса" },
            { "🐸", "Лягушка" },
            { "⚽", "Мяч" },
            { "🚀", "Ракета" },
            { "🍌", "Банан" },
            { "🍉", "Арбуз" },
            { "🏠", "Дом" },
            { "⏰", "Часы" },
            { "🎁", "Подарок" },
            { "✈️", "Самолет" },
            { "🎸", "Гитара" },
            { "🍔", "Бургер" },
            { "🍕", "Пицца" },
            { "🍦", "Мороженое" },
            { "🎈", "Шарик" },
            { "🍓", "Клубника" },
            { "🍒", "Вишня" },
            { "🍇", "Виноград" },
            { "🍍", "Ананас" },
            { "🦁", "Лев" },
            { "🐻", "Медведь" },
            { "🐼", "Панда" },
            { "🦉", "Сова" },
            { "🐠", "Рыба" },
            { "🚲", "Велосипед" },
            { "🚢", "Корабль" },
            { "🚂", "Поезд" },
            { "👑", "Корона" },
            { "🕶️", "Очки" },
            { "🎨", "Краски" },
            { "📚", "Книга" },
            { "🔔", "Колокольчик" },
            { "🕯️", "Свеча" },
            { "🌂", "Зонт" },
            { "🍩", "Пончик" },
            { "🍰", "Торт" },
            { "🍪", "Печенье" },
            { "🥕", "Морковь" },
            { "🍅", "Помидор" },
            { "🍄", "Гриб" },
            { "🌲", "Дерево" },
            { "🌸", "Цветок" },
            { "☀️", "Солнце" },
            { "🌙", "Луна" },
            { "☁️", "Облако" }
        };

        public BotRateLimiter(IConnectionMultiplexer redis)
        {
            _redis = redis;
        }

        public async Task<bool> IsBlockedAsync(string platform, long userId)
        {
            var db = _redis.GetDatabase();
            return await db.KeyExistsAsync($"bot:ratelimit:blocked:{platform}:{userId}");
        }

        public async Task<string> GetExpectedEmojiAsync(string platform, long userId)
        {
            var db = _redis.GetDatabase();
            return (string?)await db.StringGetAsync($"bot:ratelimit:expected:{platform}:{userId}") ?? "";
        }

        public async Task<ChallengeResult> GenerateChallengeAsync(string platform, long userId)
        {
            var db = _redis.GetDatabase();
            
            // Set block key
            await db.StringSetAsync($"bot:ratelimit:blocked:{platform}:{userId}", "1", TimeSpan.FromMinutes(BlockExpiryMinutes));
            
            // Pick 4 unique emojis from the pool randomly
            var rand = new Random();
            var shuffledPool = EmojiPool.Keys.OrderBy(_ => rand.Next()).ToList();
            var selectedEmojis = shuffledPool.Take(4).ToList();

            // Pick one of the selected emojis as the target
            var targetEmoji = selectedEmojis[rand.Next(selectedEmojis.Count)];
            
            await db.StringSetAsync($"bot:ratelimit:expected:{platform}:{userId}", targetEmoji, TimeSpan.FromMinutes(BlockExpiryMinutes));

            return new ChallengeResult
            {
                TargetEmoji = targetEmoji,
                TargetName = EmojiPool[targetEmoji],
                Options = selectedEmojis
            };
        }

        public async Task<bool> IncrementAndCheckLimitAsync(string platform, long userId)
        {
            var db = _redis.GetDatabase();
            var countKey = $"bot:ratelimit:count:{platform}:{userId}";
            
            var count = await db.StringIncrementAsync(countKey);
            if (count == 1)
            {
                await db.KeyExpireAsync(countKey, TimeSpan.FromSeconds(WindowSeconds));
            }

            return count > MaxMessages;
        }

        public async Task UnblockAsync(string platform, long userId)
        {
            var db = _redis.GetDatabase();
            await db.KeyDeleteAsync($"bot:ratelimit:blocked:{platform}:{userId}");
            await db.KeyDeleteAsync($"bot:ratelimit:expected:{platform}:{userId}");
            await db.KeyDeleteAsync($"bot:ratelimit:count:{platform}:{userId}");
        }
    }

    public class ChallengeResult
    {
        public string TargetEmoji { get; set; } = "";
        public string TargetName { get; set; } = "";
        public List<string> Options { get; set; } = new();
    }
}
