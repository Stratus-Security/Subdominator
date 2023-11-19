using System.Text.Json.Serialization;

namespace Subdominator;

public class Fingerprint
{
    [JsonPropertyName("cname")]
    public List<string> Cnames { get; set; } = new();

    [JsonPropertyName("a")]
    public List<string> ARecords { get; set; } = new();

    [JsonPropertyName("aaaa")]
    public List<string> AAAARecords { get; set; } = new();

    [JsonPropertyName("fingerprint")]
    [JsonConverter(typeof(SingleOrArrayConverter<string>))]
    public List<string> FingerprintTexts { get; set; }

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
}
