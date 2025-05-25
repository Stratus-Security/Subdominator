namespace Subdominator.Models;

/// <summary>
/// Represents a scan record in the database
/// </summary>
public class ScanRecord
{
    public string Id { get; set; } = string.Empty;
    public string Date { get; set; } = string.Empty;
    public int TotalDomains { get; set; }
    public int VulnerableDomains { get; set; }
    public string Settings { get; set; } = string.Empty;
    
    /// <summary>
    /// Format the scan date for display
    /// </summary>
    public string FormattedDate => DateTime.Parse(Date).ToString("yyyy-MM-dd HH:mm:ss");
}
