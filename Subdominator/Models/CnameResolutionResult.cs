namespace Subdominator.Models;

public class CnameResolutionResult
{
    public List<string> Cnames { get; set; } = new List<string>();
    public List<string> A { get; set; } = new List<string>();
    public List<string> AAAA { get; set; } = new List<string>();
    public bool IsNxdomain { get; set; } = false;
    public bool? IsDomainRegistered { get; set; } = null; // null indicates not checked
}