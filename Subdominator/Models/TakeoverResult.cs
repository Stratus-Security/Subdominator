using System.Text.Json.Serialization;

namespace Subdominator.Models;

[Serializable]
public class TakeoverResult
{
    public bool IsVulnerable { get; set; }
    public bool IsVerified { get; set; }
    public Fingerprint? Fingerprint { get; set; } 
    public List<string>? CNAMES { get; set; }
    public List<string>? A { get; set; }
    public List<string>? AAAA { get; set; }
    public MatchedRecord MatchedRecord { get; set; }
    public MatchedLocation MatchedLocation { get; set; }
}
