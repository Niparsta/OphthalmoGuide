using System.Collections.Generic;

namespace Backend.Models
{
    public class OphthalmologyKnowledge
    {
        public List<string> Symptoms { get; set; } = new();
        public List<DiseaseRecord> Diseases { get; set; } = new();
    }

    public class AnalyzeRequest
    {
        public string Text { get; set; } = string.Empty;
    }

    public class UpdateDataRequest
    {
        public List<string> Symptoms { get; set; } = new();
        public List<DiseaseRecord> Diseases { get; set; } = new();
    }

    public class ValidateDataRequest
    {
        public string Json { get; set; } = string.Empty;
    }

    public class DiseaseSymptom
    {
        public string Name { get; set; } = string.Empty;
        public bool RedFlag { get; set; }
    }

    public class DiseaseMatch
    {
        public string Disease { get; set; } = string.Empty;
        public int ThreatLevel { get; set; }
        public int MatchingSymptomsCount { get; set; }
        public int TotalDiseaseSymptomsCount { get; set; }
        public double MatchPercentage { get; set; }
        public double UserSymptomsCoverage { get; set; }
        public List<string> MatchedSymptoms { get; set; } = new();
        public List<string> AllDiseaseSymptoms { get; set; } = new();
    }


    public class AnalyzeResponse
    {
        public bool Success { get; set; }
        public List<string> ExtractedSymptoms { get; set; } = new();
        public List<string> AssumedSymptoms { get; set; } = new();
        public List<string> SuggestedDiseases { get; set; } = new();
        public List<DiseaseMatch> Results { get; set; } = new();
        public string? HistoryRecordId { get; set; }
        public string? Error { get; set; }
        public string? OllamaRawResponse { get; set; }
    }

    public class OllamaStatusResponse
    {
        public bool Accessible { get; set; }
        public List<string> AvailableModels { get; set; } = new();
        public string? Error { get; set; }
    }

    public class DiseaseRecord
    {
        public string Name { get; set; } = string.Empty;
        public int ThreatLevel { get; set; }
        public List<DiseaseSymptom> Symptoms { get; set; } = new();
    }

    public class SessionHistoryRecord
    {
        public string Id { get; set; } = string.Empty;
        public string SessionId { get; set; } = string.Empty;
        public System.DateTime Timestamp { get; set; }
        public string ComplaintText { get; set; } = string.Empty;
        public List<string> DetectedSymptoms { get; set; } = new();
        public List<string> AssumedSymptoms { get; set; } = new();
        public List<DiseaseMatch> Results { get; set; } = new();
    }
}
