using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Backend.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;

namespace Backend.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        public DbSet<SessionHistoryEntity> SessionHistories { get; set; } = null!;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            var stringListComparer = new ValueComparer<List<string>>(
                (left, right) => ReferenceEquals(left, right) || (left != null && right != null && left.SequenceEqual(right)),
                value => value == null ? 0 : value.Aggregate(0, (hash, item) => HashCode.Combine(hash, item.GetHashCode())),
                value => value == null ? new List<string>() : value.ToList());

            var diseaseMatchListComparer = new ValueComparer<List<DiseaseMatch>>(
                (left, right) => JsonSerializer.Serialize(left, (JsonSerializerOptions)null!) == JsonSerializer.Serialize(right, (JsonSerializerOptions)null!),
                value => JsonSerializer.Serialize(value, (JsonSerializerOptions)null!).GetHashCode(),
                value => JsonSerializer.Deserialize<List<DiseaseMatch>>(
                    JsonSerializer.Serialize(value, (JsonSerializerOptions)null!),
                    (JsonSerializerOptions)null!) ?? new List<DiseaseMatch>());

            modelBuilder.Entity<SessionHistoryEntity>(entity =>
            {
                entity.ToTable("session_history");
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.SessionId);

                entity.Property(e => e.Id).HasColumnName("id");
                entity.Property(e => e.SessionId).HasColumnName("session_id");
                entity.Property(e => e.Timestamp).HasColumnName("timestamp");
                entity.Property(e => e.ComplaintText).HasColumnName("complaint_text");
                entity.Property(e => e.DetectedSymptoms).HasColumnName("detected_symptoms");
                entity.Property(e => e.AssumedSymptoms).HasColumnName("assumed_symptoms");
                entity.Property(e => e.Results).HasColumnName("results");

                // Configure Value Converter to serialize List<string> to JSON string for Postgres column
                entity.Property(e => e.DetectedSymptoms)
                    .HasConversion(
                        v => JsonSerializer.Serialize(v, (JsonSerializerOptions)null!),
                        v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions)null!) ?? new List<string>()
                    )
                    .Metadata.SetValueComparer(stringListComparer);

                entity.Property(e => e.AssumedSymptoms)
                    .HasConversion(
                        v => JsonSerializer.Serialize(v, (JsonSerializerOptions)null!),
                        v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions)null!) ?? new List<string>()
                    )
                    .Metadata.SetValueComparer(stringListComparer);

                // Configure Value Converter to serialize List<DiseaseMatch> to JSON string for Postgres column
                entity.Property(e => e.Results)
                    .HasConversion(
                        v => JsonSerializer.Serialize(v, (JsonSerializerOptions)null!),
                        v => JsonSerializer.Deserialize<List<DiseaseMatch>>(v, (JsonSerializerOptions)null!) ?? new List<DiseaseMatch>()
                    )
                    .Metadata.SetValueComparer(diseaseMatchListComparer);
            });
        }
    }

    public class SessionHistoryEntity
    {
        public string Id { get; set; } = string.Empty;
        public string SessionId { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string ComplaintText { get; set; } = string.Empty;
        public List<string> DetectedSymptoms { get; set; } = new();
        public List<string> AssumedSymptoms { get; set; } = new();
        public List<DiseaseMatch> Results { get; set; } = new();
    }
}
