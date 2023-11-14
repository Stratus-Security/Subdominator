using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Subdominator;

public class Fingerprint
{
    [JsonPropertyName("cname")]
    public List<string> Cnames { get; set; }

    [JsonPropertyName("fingerprint")]
    [JsonConverter(typeof(SingleOrArrayConverter<string>))]
    public List<string> FingerprintTexts { get; set; }

    public List<Regex> FingerprintRegexes { get; set; } = new();

    [JsonPropertyName("http_status")]
    public int? HttpStatus { get; set; }

    [JsonPropertyName("nxdomain")]
    public bool Nxdomain { get; set; }

    [JsonPropertyName("service")]
    public string Service { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; }

    [JsonPropertyName("vulnerable")]
    public bool Vulnerable { get; set; }

    public void CompileRegex()
    {
        FingerprintRegexes.Clear();
        foreach (var regexText in FingerprintTexts)
        {
            if (!string.IsNullOrEmpty(regexText))
            {
                FingerprintRegexes.Add(new Regex(regexText, RegexOptions.Compiled));
            }
        }
    }
}
