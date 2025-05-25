namespace Subdominator.Models;

/// <summary>
/// Represents a data point for trend analysis
/// </summary>
public class TrendDataPoint
{
    // Used for date-based trends
    public string? Date { get; set; }
    
    // Used for category-based trends (service, risk level)
    public string? Label { get; set; }
    
    // Count of vulnerabilities
    public int Count { get; set; }
}
