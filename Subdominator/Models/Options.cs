namespace Subdominator.Models;

public class Options
{
    public string Domain { get; set; }
    public string DomainsFile { get; set; }
    public string OutputFile { get; set; }
    public string CsvHeading { get; set; }
    public int Threads { get; set; } = 50;
    public bool Verbose { get; set; }
    public bool ExcludeUnlikely { get; set; }
    public bool Validate { get; set; }
    public bool Quiet { get; set; }
    public bool AdaptiveThreads { get; set; }
    public string PreviousResults { get; set; }
    public bool AutoUpdate { get; set; }
    public string RiskLevel { get; set; } = "all";
    public string ServiceFilter { get; set; } = "";
    public bool Interactive { get; set; }
    
    // Database and trend analysis options
    public bool UseDatabase { get; set; } = true;
    public string DatabasePath { get; set; } = "vulnerabilities.db";
    public bool GenerateTrendReport { get; set; }
    public string TrendReportPath { get; set; } = "trend_report.html";
    public bool PrintTrendSummary { get; set; }
}
