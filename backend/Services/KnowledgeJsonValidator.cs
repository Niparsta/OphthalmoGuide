using System;
using System.Collections.Generic;
using System.Text.Json;

namespace Backend.Services
{
    /// Result of validating the knowledge JSON file.
    public class KnowledgeValidationResult
    {
        public List<string> Errors { get; } = new();
        public List<string> Warnings { get; } = new();
        public bool IsValid => Errors.Count == 0;
    }

    /// Validates that the ophthalmology knowledge JSON is structurally correct
    public static class KnowledgeJsonValidator
    {
        private const int MinThreatLevel = 0;
        private const int MaxThreatLevel = 3;

        public static KnowledgeValidationResult Validate(string json)
        {
            var result = new KnowledgeValidationResult();

            if (string.IsNullOrWhiteSpace(json))
            {
                result.Errors.Add("File is empty.");
                return result;
            }

            JsonDocument document;
            try
            {
                document = JsonDocument.Parse(json);
            }
            catch (JsonException ex)
            {
                result.Errors.Add($"Invalid JSON syntax: {ex.Message}");
                return result;
            }

            using (document)
            {
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    result.Errors.Add($"Root element must be a JSON object, but found '{root.ValueKind}'.");
                    return result;
                }

                var knownSymptoms = ValidateSymptoms(root, result);
                ValidateDiseases(root, result, knownSymptoms);
            }

            return result;
        }

        private static HashSet<string> ValidateSymptoms(JsonElement root, KnowledgeValidationResult result)
        {
            var knownSymptoms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (!TryGetProperty(root, "symptoms", out var symptoms))
            {
                result.Errors.Add("Missing required property 'symptoms'.");
                return knownSymptoms;
            }

            if (symptoms.ValueKind != JsonValueKind.Array)
            {
                result.Errors.Add($"Property 'symptoms' must be an array, but found '{symptoms.ValueKind}'.");
                return knownSymptoms;
            }

            if (symptoms.GetArrayLength() == 0)
            {
                result.Warnings.Add("Property 'symptoms' is an empty array.");
            }

            var index = 0;
            foreach (var symptom in symptoms.EnumerateArray())
            {
                if (symptom.ValueKind != JsonValueKind.String)
                {
                    result.Errors.Add($"symptoms[{index}] must be a string, but found '{symptom.ValueKind}'.");
                }
                else
                {
                    var value = symptom.GetString();
                    if (string.IsNullOrWhiteSpace(value))
                    {
                        result.Errors.Add($"symptoms[{index}] must not be empty.");
                    }
                    else if (!knownSymptoms.Add(value))
                    {
                        result.Warnings.Add($"Duplicate symptom in 'symptoms': '{value}'.");
                    }
                }

                index++;
            }

            return knownSymptoms;
        }

        private static void ValidateDiseases(JsonElement root, KnowledgeValidationResult result, HashSet<string> knownSymptoms)
        {
            if (!TryGetProperty(root, "diseases", out var diseases))
            {
                result.Errors.Add("Missing required property 'diseases'.");
                return;
            }

            if (diseases.ValueKind != JsonValueKind.Array)
            {
                result.Errors.Add($"Property 'diseases' must be an array, but found '{diseases.ValueKind}'.");
                return;
            }

            if (diseases.GetArrayLength() == 0)
            {
                result.Warnings.Add("Property 'diseases' is an empty array.");
            }

            var diseaseNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var index = 0;
            foreach (var disease in diseases.EnumerateArray())
            {
                ValidateDisease(disease, index, result, knownSymptoms, diseaseNames);
                index++;
            }
        }

        private static void ValidateDisease(
            JsonElement disease,
            int index,
            KnowledgeValidationResult result,
            HashSet<string> knownSymptoms,
            HashSet<string> diseaseNames)
        {
            if (disease.ValueKind != JsonValueKind.Object)
            {
                result.Errors.Add($"diseases[{index}] must be an object, but found '{disease.ValueKind}'.");
                return;
            }

            var diseaseName = $"diseases[{index}]";
            if (!TryGetProperty(disease, "name", out var name) || name.ValueKind != JsonValueKind.String)
            {
                result.Errors.Add($"{diseaseName}.name is required and must be a string.");
            }
            else
            {
                var value = name.GetString();
                if (string.IsNullOrWhiteSpace(value))
                {
                    result.Errors.Add($"{diseaseName}.name must not be empty.");
                }
                else
                {
                    diseaseName = $"diseases[{index}] ('{value}')";
                    if (!diseaseNames.Add(value))
                    {
                        result.Warnings.Add($"Duplicate disease name: '{value}'.");
                    }
                }
            }

            if (!TryGetProperty(disease, "threatLevel", out var threatLevel) || threatLevel.ValueKind != JsonValueKind.Number)
            {
                result.Errors.Add($"{diseaseName}.threatLevel is required and must be a number.");
            }
            else if (!threatLevel.TryGetInt32(out var level))
            {
                result.Errors.Add($"{diseaseName}.threatLevel must be an integer.");
            }
            else if (level < MinThreatLevel || level > MaxThreatLevel)
            {
                result.Errors.Add($"{diseaseName}.threatLevel must be between {MinThreatLevel} and {MaxThreatLevel}, but was {level}.");
            }

            ValidateDiseaseSymptoms(disease, diseaseName, result, knownSymptoms);
        }

        private static void ValidateDiseaseSymptoms(
            JsonElement disease,
            string diseaseName,
            KnowledgeValidationResult result,
            HashSet<string> knownSymptoms)
        {
            if (!TryGetProperty(disease, "symptoms", out var symptoms))
            {
                result.Errors.Add($"{diseaseName}.symptoms is required.");
                return;
            }

            if (symptoms.ValueKind != JsonValueKind.Array)
            {
                result.Errors.Add($"{diseaseName}.symptoms must be an array, but found '{symptoms.ValueKind}'.");
                return;
            }

            var index = 0;
            foreach (var symptom in symptoms.EnumerateArray())
            {
                var symptomName = $"{diseaseName}.symptoms[{index}]";
                if (symptom.ValueKind != JsonValueKind.Object)
                {
                    result.Errors.Add($"{symptomName} must be an object, but found '{symptom.ValueKind}'.");
                    index++;
                    continue;
                }

                if (!TryGetProperty(symptom, "name", out var name) || name.ValueKind != JsonValueKind.String)
                {
                    result.Errors.Add($"{symptomName}.name is required and must be a string.");
                }
                else
                {
                    var value = name.GetString();
                    if (string.IsNullOrWhiteSpace(value))
                    {
                        result.Errors.Add($"{symptomName}.name must not be empty.");
                    }
                    else if (knownSymptoms.Count > 0 && !knownSymptoms.Contains(value))
                    {
                        result.Warnings.Add($"{symptomName}.name '{value}' is not present in the global 'symptoms' list.");
                    }
                }

                if (TryGetProperty(symptom, "redFlag", out var redFlag)
                    && redFlag.ValueKind != JsonValueKind.True
                    && redFlag.ValueKind != JsonValueKind.False)
                {
                    result.Errors.Add($"{symptomName}.redFlag must be a boolean, but found '{redFlag.ValueKind}'.");
                }

                index++;
            }
        }

        private static bool TryGetProperty(JsonElement element, string propertyName, out JsonElement value)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }

            value = default;
            return false;
        }
    }
}
