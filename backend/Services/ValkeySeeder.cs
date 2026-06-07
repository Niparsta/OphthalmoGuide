using System.IO;
using System.Text;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace Backend.Services
{
    public static class ValkeySeeder
    {
        public const string KnowledgeKey = "ophthalmoguide:knowledge";

        public static bool Seed(IConnectionMultiplexer redis, string knowledgeJsonPath, ILogger? logger = null)
        {
            var db = redis.GetDatabase();
            var existing = db.StringGet(KnowledgeKey);
            if (!existing.IsNullOrEmpty)
            {
                return false;
            }

            if (!File.Exists(knowledgeJsonPath))
            {
                throw new FileNotFoundException($"Cannot find knowledge JSON file to seed Valkey at: {knowledgeJsonPath}");
            }

            var json = File.ReadAllText(knowledgeJsonPath, Encoding.UTF8);

            var validation = KnowledgeJsonValidator.Validate(json);

            foreach (var warning in validation.Warnings)
            {
                logger?.LogWarning("Knowledge JSON validation warning: {Warning}", warning);
            }

            if (!validation.IsValid)
            {
                foreach (var error in validation.Errors)
                {
                    logger?.LogError("Knowledge JSON validation error: {Error}", error);
                }

                throw new InvalidDataException(
                    $"Knowledge JSON at '{knowledgeJsonPath}' failed structural validation with " +
                    $"{validation.Errors.Count} error(s). Data was not loaded into Valkey.");
            }

            db.StringSet(KnowledgeKey, json);
            return true;
        }
    }
}
