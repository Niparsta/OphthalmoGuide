using System;
using System.Collections.Generic;
using System.IO;
using Backend.Models;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace Backend.Services
{
    public class PdfExportService
    {
        private const float BrandLogoHeight = 46;
        private const float SectionTitleWithContentMinHeight = 56f;
        private const float SectionTableMinHeight = 100f;
        private static readonly string LogoPath = Path.Combine(AppContext.BaseDirectory, "Assets", "Images", "logo_black.png");

        static PdfExportService()
        {
            QuestPDF.Settings.License = LicenseType.Community;
        }

        public static string GetFileName(DateTime reportTime)
        {
            return $"OphthalmoGuide_{reportTime:yyyyMMdd_HHmmss}.pdf";
        }

        public byte[] GenerateReportPdf(string recordId, string complaintText, List<string> detectedSymptoms, List<string> assumedSymptoms, List<DiseaseMatch> results)
        {
            var reportTime = GetReportTime();

            var document = Document.Create(container =>
            {
                container.Page(page =>
                {
                    page.Size(PageSizes.A4);
                    page.Margin(2, Unit.Centimetre);
                    page.PageColor(Colors.White);
                    page.DefaultTextStyle(x => x.FontFamily("Arial").FontSize(10));

                    // Header
                    page.Header()
                        .Column(headerColumn =>
                        {
                            headerColumn.Item().Row(row =>
                            {
                                row.RelativeItem().Column(column =>
                                {
                                    column.Item()
                                        .Height(BrandLogoHeight)
                                        .Image(LogoPath)
                                        .FitHeight();

                                    column.Item().PaddingTop(4).Text("Информационно-справочная система предварительной диагностики офтальмологических заболеваний")
                                        .FontSize(9)
                                        .FontColor("#64748B");
                                });

                                row.ConstantItem(140).AlignRight().AlignMiddle().Column(column =>
                                {
                                    column.Item().Text($"Дата: {reportTime:dd.MM.yyyy}")
                                        .FontSize(9)
                                        .FontColor(Colors.Grey.Darken2);
                                    column.Item().Text($"Время: {reportTime:HH:mm:ss} мск")
                                        .FontSize(9)
                                        .FontColor(Colors.Grey.Darken2);
                                });
                            });

                            headerColumn.Item().PaddingTop(0.2f, Unit.Centimetre).LineHorizontal(1).LineColor(Colors.Grey.Lighten2);
                        });

                    // Content
                    page.Content()
                        .PaddingBottom(1, Unit.Centimetre)
                        .Column(column =>
                        {
                            column.Item().PaddingBottom(15);

                            // Section 1
                            RenderReportSection(column, "1. Анамнез (жалоба пациента)", SectionTitleWithContentMinHeight, section =>
                            {
                                section.Item().PaddingTop(5).PaddingBottom(15).Background(Colors.Grey.Lighten4).Padding(10).Text(complaintText).Italic();
                            });

                            // Section 2
                            RenderReportSection(column, "2. Выявленные симптомы", SectionTitleWithContentMinHeight, section =>
                            {
                                section.Item().PaddingTop(5).PaddingBottom(15).Row(row =>
                                {
                                    row.RelativeItem().Column(symptomCol =>
                                    {
                                        symptomCol.Item().Text("Выделенные клинические симптомы:").Bold().FontSize(10).FontColor(Colors.Grey.Darken3);
                                        if (detectedSymptoms == null || detectedSymptoms.Count == 0)
                                        {
                                            symptomCol.Item().PaddingLeft(10).Text("Симптомы не обнаружены.").Italic().FontColor(Colors.Grey.Medium);
                                        }
                                        else
                                        {
                                            symptomCol.Item().PaddingLeft(10).Text(string.Join(", ", detectedSymptoms)).Bold().FontColor(Colors.Green.Darken3);
                                        }

                                        if (assumedSymptoms != null && assumedSymptoms.Count > 0)
                                        {
                                            symptomCol.Item().PaddingTop(8).Text("Косвенные клинические симптомы:").Bold().FontSize(10).FontColor(Colors.Grey.Darken3);
                                            symptomCol.Item().PaddingLeft(10).Text(string.Join(", ", assumedSymptoms)).Bold().FontColor(Colors.Blue.Darken3);
                                        }
                                    });
                                });
                            });

                            var filteredResults = new List<DiseaseMatch>();
                            double topPercent = 0;
                            if (results != null && results.Count > 0)
                            {
                                var sorted = results
                                    .Where(r => r.MatchPercentage > 0)
                                    .OrderByDescending(r => r.MatchPercentage)
                                    .ToList();
                                if (sorted.Count > 0)
                                {
                                    topPercent = sorted[0].MatchPercentage;
                                    filteredResults = sorted.Take(5).ToList();
                                }
                            }

                            // Section 3
                            RenderReportSection(column, "3. Предполагаемые причины", SectionTableMinHeight, section =>
                            {
                                section.Item().PaddingTop(5).Table(table =>
                                {
                                    // Columns definition
                                    table.ColumnsDefinition(columns =>
                                    {
                                        columns.RelativeColumn(3.0f); // Заболевание
                                        columns.RelativeColumn(2.0f); // Диффер. вес
                                        columns.RelativeColumn(2.6f); // Совпадение по симптомам
                                        columns.RelativeColumn(2.2f); // Уровень угрозы
                                        columns.RelativeColumn(3.2f); // Совпавшие симптомы
                                    });

                                    // Header
                                    table.Header(header =>
                                    {
                                        header.Cell().Background("#e0f2fe").Padding(5).Text("Заболевание").Bold().FontColor("#0369a1");
                                        header.Cell().Background("#e0f2fe").Padding(5).Text("Диффер. вес").Bold().FontColor("#0369a1");
                                        header.Cell().Background("#e0f2fe").Padding(5).Text("Совпадение по симптомам").Bold().FontColor("#0369a1");
                                        header.Cell().Background("#e0f2fe").Padding(5).Text("Уровень угрозы").Bold().FontColor("#0369a1");
                                        header.Cell().Background("#e0f2fe").Padding(5).Text("Совпавшие симптомы").Bold().FontColor("#0369a1");
                                    });

                                    // Rows
                                    for (int i = 0; i < filteredResults.Count; i++)
                                    {
                                        var match = filteredResults[i];

                                        table.Cell().BorderBottom(1).BorderColor(Colors.Grey.Lighten2).Padding(5).Text(match.Disease);

                                        // Differential weight normalized to 0.00 - 1.00
                                        double confidenceRatio = topPercent > 0 ? (match.MatchPercentage / topPercent) : 0;
                                        string diffWeightStr = confidenceRatio.ToString("F2", System.Globalization.CultureInfo.InvariantCulture);
                                        table.Cell().BorderBottom(1).BorderColor(Colors.Grey.Lighten2).Padding(5).Text(diffWeightStr).FontColor(Colors.Grey.Darken3);

                                        // Absolute match percentage and symptom counts
                                        table.Cell().BorderBottom(1).BorderColor(Colors.Grey.Lighten2).Padding(5)
                                            .Text($"{match.MatchPercentage}% ({match.MatchingSymptomsCount} из {match.TotalDiseaseSymptomsCount})")
                                            .FontColor(Colors.Grey.Darken3);

                                        // Threat Level Badge
                                        var levelText = GetThreatLevelText(match.ThreatLevel);
                                        var badgeColor = GetThreatLevelColor(match.ThreatLevel);
                                        table.Cell().BorderBottom(1).BorderColor(Colors.Grey.Lighten2).Padding(5).Text(levelText).Bold().FontColor(badgeColor);

                                        table.Cell().BorderBottom(1).BorderColor(Colors.Grey.Lighten2).Padding(5).Text(string.Join(", ", match.MatchedSymptoms ?? [])).FontSize(8).FontColor(Colors.Grey.Darken2);
                                    }
                                });
                            });

                            // Section 4
                            var maxThreatLevel = filteredResults.Count > 0 ? filteredResults.Max(r => r.ThreatLevel) : 0;
                            RenderReportSectionEntire(column, "4. Рекомендации", section =>
                            {
                                section.Item().PaddingTop(5).Text(x =>
                                {
                                    x.Span("Общий уровень угрозы: ").Bold();
                                    x.Span(GetThreatLevelText(maxThreatLevel)).Bold().FontColor(GetThreatLevelColor(maxThreatLevel));
                                });
                                section.Item().PaddingTop(5).Background(Colors.Grey.Lighten4).Padding(10).Column(adviceCol =>
                                {
                                    adviceCol.Item().Text(GetThreatLevelAdvice(maxThreatLevel)).Italic();

                                    if (maxThreatLevel == 3)
                                    {
                                        adviceCol.Item().PaddingTop(6).Text(text =>
                                        {
                                            text.Span("112").Bold().FontColor(Colors.Red.Darken2);
                                            text.Span(" – единый номер вызова экстренных оперативных служб").FontSize(8.5f);
                                        });
                                        adviceCol.Item().PaddingTop(3).Text(text =>
                                        {
                                            text.Span("103").Bold().FontColor(Colors.Red.Darken2);
                                            text.Span(" – общефедеральный номер вызова скорой медицинской помощи").FontSize(8.5f);
                                        });
                                    }
                                });
                            }, paddingTop: 15);
                        });

                    // Footer
                    page.Footer()
                        .AlignCenter()
                        .Column(column =>
                        {
                            column.Item().LineHorizontal(1).LineColor(Colors.Grey.Lighten2);
                            column.Item().PaddingTop(5).Text("Сервис носит исключительно информационно-справочный характер и не является медицинским изделием или системой поддержки принятия врачебных решений. Представленные сведения не являются диагнозом, назначением или руководством к самолечению и не заменяют очную консультацию квалифицированного врача. Полнота и точность представленной информации не гарантируются; ответственность за её самостоятельную интерпретацию и принятые на её основе решения несёт пользователь. При любых симптомах обратитесь к врачу-специалисту, а в неотложных случаях – вызовите скорую медицинскую помощь (112/103).")
                                .FontSize(5.8f)
                                .FontColor(Colors.Grey.Medium)
                                .Justify();

                            column.Item().PaddingTop(5).Row(row =>
                            {
                                row.RelativeItem().AlignLeft().AlignMiddle().Text(x =>
                                {
                                    x.Span("Страница ");
                                    x.CurrentPageNumber();
                                    x.Span(" из ");
                                    x.TotalPages();
                                });
                                row.RelativeItem().AlignRight().AlignMiddle().Text(recordId)
                                    .FontSize(9)
                                    .FontColor(Colors.Grey.Darken2);
                            });
                        });
                });
            });

            using (var stream = new MemoryStream())
            {
                document.GeneratePdf(stream);
                return stream.ToArray();
            }
        }

        private static void RenderReportSection(
            ColumnDescriptor parent,
            string title,
            float keepTogetherMinHeight,
            Action<ColumnDescriptor> buildContent,
            float paddingTop = 0)
        {
            var sectionItem = parent.Item();
            if (paddingTop > 0)
            {
                sectionItem = sectionItem.PaddingTop(paddingTop);
            }

            sectionItem
                .EnsureSpace(keepTogetherMinHeight)
                .Column(section =>
                {
                    section.Item().Text(title).FontSize(14).Bold().FontColor("#0284c7");
                    buildContent(section);
                });
        }

        private static void RenderReportSectionEntire(
            ColumnDescriptor parent,
            string title,
            Action<ColumnDescriptor> buildContent,
            float paddingTop = 0)
        {
            var sectionItem = parent.Item();
            if (paddingTop > 0)
            {
                sectionItem = sectionItem.PaddingTop(paddingTop);
            }

            sectionItem
                .ShowEntire()
                .Column(section =>
                {
                    section.Item().Text(title).FontSize(14).Bold().FontColor("#0284c7");
                    buildContent(section);
                });
        }

        private static DateTime GetReportTime()
        {
            var configuredTimeZone = Environment.GetEnvironmentVariable("TZ") ?? "Europe/Moscow";
            foreach (var timeZoneId in new[] { configuredTimeZone, "Europe/Moscow", "Russian Standard Time" })
            {
                try
                {
                    return TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, TimeZoneInfo.FindSystemTimeZoneById(timeZoneId));
                }
                catch (TimeZoneNotFoundException)
                {
                }
                catch (InvalidTimeZoneException)
                {
                }
            }

            return DateTime.Now;
        }

        private string GetThreatLevelText(int level)
        {
            return level switch
            {
                0 => "Нет угрозы",
                1 => "Низкий",
                2 => "Средний",
                3 => "Критический",
                _ => "Неизвестно"
            };
        }

        private string GetThreatLevelAdvice(int level)
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

        private static string GetConfidenceWord(double confidence)
        {
            if (confidence >= 80) return "высокое";
            if (confidence >= 45) return "среднее";
            return "низкое";
        }

        private string GetThreatLevelColor(int level)
        {
            return level switch
            {
                0 => Colors.Green.Darken2,
                1 => Colors.Blue.Darken2,
                2 => Colors.Orange.Darken2,
                3 => Colors.Red.Darken2,
                _ => Colors.Grey.Darken2
            };
        }
    }
}
