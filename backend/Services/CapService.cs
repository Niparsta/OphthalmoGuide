using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace backend.Services
{
    public class CapChallenge
    {
        public string algorithm { get; set; } = "SHA-256";
        public string challenge { get; set; } = "";
        public string salt { get; set; } = "";
        public string signature { get; set; } = "";
        public int maxnumber { get; set; } = 50000;
    }

    public class CapPayload
    {
        public string algorithm { get; set; } = "";
        public string challenge { get; set; } = "";
        public string salt { get; set; } = "";
        public string signature { get; set; } = "";
        public int number { get; set; }
    }

    public class CapService
    {
        private readonly string _secret;

        public CapService(string secret)
        {
            _secret = string.IsNullOrEmpty(secret) ? "default_cap_secret_key_12345" : secret;
        }

        public CapChallenge GenerateChallenge(int maxNumber = 50000)
        {
            var saltBytes = new byte[16];
            RandomNumberGenerator.Fill(saltBytes);
            var randomHex = Convert.ToHexString(saltBytes).ToLower();

            // Set expiration to 15 minutes from now
            var expires = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds();
            var salt = $"{randomHex}?expires={expires}";

            // Select a random number between 1 and maxNumber
            int number = RandomNumberGenerator.GetInt32(1, maxNumber);

            // Compute challenge = SHA256(salt + number)
            var challengeInput = salt + number.ToString();
            var challengeHash = SHA256.HashData(Encoding.UTF8.GetBytes(challengeInput));
            var challenge = Convert.ToHexString(challengeHash).ToLower();

            // Compute signature = HMAC-SHA256(challenge, secret)
            var signature = ComputeHmac(challenge);

            return new CapChallenge
            {
                challenge = challenge,
                salt = salt,
                signature = signature,
                maxnumber = maxNumber
            };
        }

        public bool VerifyPayload(CapPayload payload)
        {
            if (payload == null || string.IsNullOrWhiteSpace(payload.challenge) || string.IsNullOrWhiteSpace(payload.salt) || string.IsNullOrWhiteSpace(payload.signature))
            {
                return false;
            }

            // 1. Check expiration
            var parts = payload.salt.Split("?expires=");
            if (parts.Length != 2 || !long.TryParse(parts[1], out var expires))
            {
                return false;
            }

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now > expires)
            {
                return false; // Expired
            }

            // 2. Verify signature
            var expectedSignature = ComputeHmac(payload.challenge);
            if (!string.Equals(expectedSignature, payload.signature, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // 3. Verify solution: SHA256(salt + number) == challenge
            var challengeInput = payload.salt + payload.number.ToString();
            var challengeHash = SHA256.HashData(Encoding.UTF8.GetBytes(challengeInput));
            var challengeHex = Convert.ToHexString(challengeHash).ToLower();

            if (!string.Equals(challengeHex, payload.challenge, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return true;
        }

        private string ComputeHmac(string input)
        {
            var keyBytes = Encoding.UTF8.GetBytes(_secret);
            var inputBytes = Encoding.UTF8.GetBytes(input);
            using var hmac = new HMACSHA256(keyBytes);
            var hashBytes = hmac.ComputeHash(inputBytes);
            return Convert.ToHexString(hashBytes).ToLower();
        }
    }
}
