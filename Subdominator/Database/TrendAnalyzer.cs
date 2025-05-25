using ScottPlot;
using Subdominator.Models;

namespace Subdominator.Database;

/// <summary>
/// Provides trend analysis and reporting functionality for vulnerability data
/// </summary>
public class TrendAnalyzer
{
    private readonly VulnerabilityDatabase _db;
    
    public TrendAnalyzer(VulnerabilityDatabase db)
    {
        _db = db;
    }
    
    /// <summary>
    /// Generate a trend report based on scan history
    /// </summary>
    public void GenerateTrendReport(string outputPath = "trend_report.html")
    {
        var dateData = _db.GetVulnerabilityTrendByDate().ToList();
        var serviceData = _db.GetVulnerabilityTrendByService().ToList();
        var riskData = _db.GetVulnerabilityTrendByRiskLevel().ToList();
        var scans = _db.GetAllScans().ToList();
        
        if (!dateData.Any() || !scans.Any())
        {
            Console.WriteLine("Not enough data to generate a trend report.");
            return;
        }
        
        // Create HTML report
        var html = new StringBuilder();
        html.AppendLine("<!DOCTYPE html>");
        html.AppendLine("<html lang=\"en\">");
        html.AppendLine("<head>");
        html.AppendLine("  <meta charset=\"UTF-8\">");
        html.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        html.AppendLine("  <title>Subdominator Trend Analysis Report</title>");
        html.AppendLine("  <style>");
        html.AppendLine("    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }");
        html.AppendLine("    h1, h2, h3 { color: #2c3e50; }");
        html.AppendLine("    .container { max-width: 1200px; margin: 0 auto; }");
        html.AppendLine("    .card { background: #fff; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 20px; }");
        html.AppendLine("    .chart { width: 100%; height: 400px; margin: 20px 0; }");
        html.AppendLine("    table { width: 100%; border-collapse: collapse; margin: 20px 0; }");
        html.AppendLine("    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }");
        html.AppendLine("    th { background-color: #f2f2f2; }");
        html.AppendLine("    tr:hover { background-color: #f5f5f5; }");
        html.AppendLine("    .risk-critical { color: #7b241c; font-weight: bold; }");
        html.AppendLine("    .risk-high { color: #c0392b; }");
        html.AppendLine("    .risk-medium { color: #d4ac0d; }");
        html.AppendLine("    .risk-low { color: #2471a3; }");
        html.AppendLine("    .header { display: flex; justify-content: space-between; align-items: center; }");
        html.AppendLine("    .summary-box { display: inline-block; padding: 15px; margin: 10px; border-radius: 5px; color: white; text-align: center; min-width: 150px; }");
        html.AppendLine("    .summary-number { font-size: 24px; font-weight: bold; margin: 5px 0; }");
        html.AppendLine("    .summary-label { font-size: 14px; }");
        html.AppendLine("    .total-scans { background-color: #3498db; }");
        html.AppendLine("    .total-vulnerabilities { background-color: #e74c3c; }");
        html.AppendLine("    .scans-period { background-color: #2ecc71; }");
        html.AppendLine("  </style>");
        html.AppendLine("  <script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>");
        html.AppendLine("</head>");
        html.AppendLine("<body>");
        html.AppendLine("  <div class=\"container\">");
        html.AppendLine("    <div class=\"header\">");
        html.AppendLine("      <h1>Subdominator Trend Analysis Report</h1>");
        html.AppendLine($"      <p>Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
        html.AppendLine("    </div>");
        
        // Summary section
        html.AppendLine("    <div class=\"card\">");
        html.AppendLine("      <h2>Summary</h2>");
        html.AppendLine("      <div>");
        html.AppendLine($"        <div class=\"summary-box total-scans\"><div class=\"summary-number\">{scans.Count}</div><div class=\"summary-label\">Total Scans</div></div>");
        html.AppendLine($"        <div class=\"summary-box total-vulnerabilities\"><div class=\"summary-number\">{dateData.Sum(d => d.Count)}</div><div class=\"summary-label\">Total Vulnerabilities</div></div>");
        
        var firstScan = DateTime.Parse(scans.Last().Date);
        var lastScan = DateTime.Parse(scans.First().Date);
        var daysDifference = (lastScan - firstScan).Days + 1;
        html.AppendLine($"        <div class=\"summary-box scans-period\"><div class=\"summary-number\">{daysDifference}</div><div class=\"summary-label\">Days Monitored</div></div>");
        html.AppendLine("      </div>");
        html.AppendLine("    </div>");
        
        // Trend over time chart
        html.AppendLine("    <div class=\"card\">");
        html.AppendLine("      <h2>Vulnerability Trend Over Time</h2>");
        html.AppendLine("      <canvas id=\"timeChart\" class=\"chart\"></canvas>");
        html.AppendLine("    </div>");
        
        // Risk level distribution chart
        html.AppendLine("    <div class=\"card\">");
        html.AppendLine("      <h2>Vulnerabilities by Risk Level</h2>");
        html.AppendLine("      <canvas id=\"riskChart\" class=\"chart\"></canvas>");
        html.AppendLine("    </div>");
        
        // Service distribution chart
        html.AppendLine("    <div class=\"card\">");
        html.AppendLine("      <h2>Top 10 Services with Vulnerabilities</h2>");
        html.AppendLine("      <canvas id=\"serviceChart\" class=\"chart\"></canvas>");
        html.AppendLine("    </div>");
        
        // Recent scans table
        html.AppendLine("    <div class=\"card\">");
        html.AppendLine("      <h2>Recent Scans</h2>");
        html.AppendLine("      <table>");
        html.AppendLine("        <thead>");
        html.AppendLine("          <tr>");
        html.AppendLine("            <th>Date</th>");
        html.AppendLine("            <th>Total Domains</th>");
        html.AppendLine("            <th>Vulnerable Domains</th>");
        html.AppendLine("            <th>Vulnerability Rate</th>");
        html.AppendLine("          </tr>");
        html.AppendLine("        </thead>");
        html.AppendLine("        <tbody>");
        
        foreach (var scan in scans.Take(10))
        {
            var rate = scan.TotalDomains > 0 
                ? (double)scan.VulnerableDomains / scan.TotalDomains * 100 
                : 0;
            
            html.AppendLine("          <tr>");
            html.AppendLine($"            <td>{scan.FormattedDate}</td>");
            html.AppendLine($"            <td>{scan.TotalDomains}</td>");
            html.AppendLine($"            <td>{scan.VulnerableDomains}</td>");
            html.AppendLine($"            <td>{rate:F2}%</td>");
            html.AppendLine("          </tr>");
        }
        
        html.AppendLine("        </tbody>");
        html.AppendLine("      </table>");
        html.AppendLine("    </div>");
        
        // JavaScript for charts
        html.AppendLine("    <script>");
        
        // Time chart data
        html.AppendLine("      const timeCtx = document.getElementById('timeChart').getContext('2d');");
        html.AppendLine("      const timeChart = new Chart(timeCtx, {");
        html.AppendLine("        type: 'line',");
        html.AppendLine("        data: {");
        html.AppendLine($"          labels: [{string.Join(", ", dateData.Select(d => $"'{d.Date}'"))}],");
        html.AppendLine("          datasets: [{");
        html.AppendLine("            label: 'Vulnerabilities',");
        html.AppendLine("            data: [" + string.Join(", ", dateData.Select(d => d.Count)) + "],");
        html.AppendLine("            borderColor: 'rgb(75, 192, 192)',");
        html.AppendLine("            tension: 0.1");
        html.AppendLine("          }]");
        html.AppendLine("        },");
        html.AppendLine("        options: {");
        html.AppendLine("          scales: {");
        html.AppendLine("            y: {");
        html.AppendLine("              beginAtZero: true");
        html.AppendLine("            }");
        html.AppendLine("          }");
        html.AppendLine("        }");
        html.AppendLine("      });");
        
        // Risk chart data
        html.AppendLine("      const riskCtx = document.getElementById('riskChart').getContext('2d');");
        html.AppendLine("      const riskChart = new Chart(riskCtx, {");
        html.AppendLine("        type: 'pie',");
        html.AppendLine("        data: {");
        html.AppendLine($"          labels: [{string.Join(", ", riskData.Select(d => $"'{d.Label}'"))}],");
        html.AppendLine("          datasets: [{");
        html.AppendLine("            data: [" + string.Join(", ", riskData.Select(d => d.Count)) + "],");
        html.AppendLine("            backgroundColor: [");
        html.AppendLine("              '#7b241c', // Critical");
        html.AppendLine("              '#c0392b', // High");
        html.AppendLine("              '#d4ac0d', // Medium");
        html.AppendLine("              '#2471a3', // Low");
        html.AppendLine("              '#95a5a6'  // Other");
        html.AppendLine("            ]");
        html.AppendLine("          }]");
        html.AppendLine("        }");
        html.AppendLine("      });");
        
        // Service chart data
        html.AppendLine("      const serviceCtx = document.getElementById('serviceChart').getContext('2d');");
        html.AppendLine("      const serviceChart = new Chart(serviceCtx, {");
        html.AppendLine("        type: 'bar',");
        html.AppendLine("        data: {");
        html.AppendLine($"          labels: [{string.Join(", ", serviceData.Select(d => $"'{d.Label}'"))}],");
        html.AppendLine("          datasets: [{");
        html.AppendLine("            label: 'Vulnerabilities',");
        html.AppendLine("            data: [" + string.Join(", ", serviceData.Select(d => d.Count)) + "],");
        html.AppendLine("            backgroundColor: 'rgba(54, 162, 235, 0.8)'");
        html.AppendLine("          }]");
        html.AppendLine("        },");
        html.AppendLine("        options: {");
        html.AppendLine("          scales: {");
        html.AppendLine("            y: {");
        html.AppendLine("              beginAtZero: true");
        html.AppendLine("            }");
        html.AppendLine("          }");
        html.AppendLine("        }");
        html.AppendLine("      });");
        
        html.AppendLine("    </script>");
        html.AppendLine("  </div>");
        html.AppendLine("</body>");
        html.AppendLine("</html>");
        
        // Write the report to file
        File.WriteAllText(outputPath, html.ToString());
        
        Console.WriteLine($"Trend report generated: {Path.GetFullPath(outputPath)}");
    }
    
    /// <summary>
    /// Generate charts for trend analysis
    /// </summary>
    public void GenerateTrendCharts(string outputDir = "trend_charts")
    {
        var dateData = _db.GetVulnerabilityTrendByDate().ToList();
        var serviceData = _db.GetVulnerabilityTrendByService().ToList();
        var riskData = _db.GetVulnerabilityTrendByRiskLevel().ToList();
        
        if (!dateData.Any())
        {
            Console.WriteLine("Not enough data to generate trend charts.");
            return;
        }
        
        // Create output directory if it doesn't exist
        if (!Directory.Exists(outputDir))
        {
            Directory.CreateDirectory(outputDir);
        }
        
        // Vulnerability trend over time
        var timePlot = new Plot(600, 400);
        var xPositions = Enumerable.Range(0, dateData.Count).ToArray();
        var yValues = dateData.Select(d => (double)d.Count).ToArray();
        var xLabels = dateData.Select(d => d.Date).ToArray();
        
        timePlot.Add.Scatter(xPositions, yValues);
        timePlot.SavePng(Path.Combine(outputDir, "trend_over_time.png"));
        
        // Risk level distribution
        var riskPlot = new Plot(600, 400);
        var riskValues = riskData.Select(d => (double)d.Count).ToArray();
        var riskLabels = riskData.Select(d => d.Label).ToArray();
        
        riskPlot.Add.Pie(riskValues);
        riskPlot.SavePng(Path.Combine(outputDir, "risk_distribution.png"));
        
        // Service distribution
        var servicePlot = new Plot(600, 400);
        var serviceValues = serviceData.Select(d => (double)d.Count).ToArray();
        var servicePositions = Enumerable.Range(0, serviceData.Count).ToArray();
        var serviceLabels = serviceData.Select(d => d.Label).ToArray();
        
        servicePlot.Add.Bars(servicePositions, serviceValues);
        servicePlot.SavePng(Path.Combine(outputDir, "service_distribution.png"));
        
        Console.WriteLine($"Trend charts generated in directory: {Path.GetFullPath(outputDir)}");
    }
    
    /// <summary>
    /// Print a summary of trend analysis to the console
    /// </summary>
    public void PrintTrendSummary()
    {
        var dateData = _db.GetVulnerabilityTrendByDate().ToList();
        var serviceData = _db.GetVulnerabilityTrendByService().ToList();
        var riskData = _db.GetVulnerabilityTrendByRiskLevel().ToList();
        var scans = _db.GetAllScans().ToList();
        
        if (!dateData.Any() || !scans.Any())
        {
            Console.WriteLine("Not enough data to generate a trend summary.");
            return;
        }
        
        Console.WriteLine("\n============ VULNERABILITY TREND SUMMARY ============");
        Console.WriteLine($"Total Scans: {scans.Count}");
        Console.WriteLine($"Total Vulnerabilities: {dateData.Sum(d => d.Count)}");
        
        var firstScan = DateTime.Parse(scans.Last().Date);
        var lastScan = DateTime.Parse(scans.First().Date);
        Console.WriteLine($"Monitoring Period: {firstScan:yyyy-MM-dd} to {lastScan:yyyy-MM-dd} ({(lastScan - firstScan).Days + 1} days)");
        
        Console.WriteLine("\nVulnerabilities by Risk Level:");
        foreach (var risk in riskData)
        {
            Console.WriteLine($"  {risk.Label}: {risk.Count}");
        }
        
        Console.WriteLine("\nTop 5 Vulnerable Services:");
        foreach (var service in serviceData.Take(5))
        {
            Console.WriteLine($"  {service.Label}: {service.Count}");
        }
        
        Console.WriteLine("\nRecent Trend (last 5 data points):");
        foreach (var point in dateData.TakeLast(5))
        {
            Console.WriteLine($"  {point.Date}: {point.Count} vulnerabilities");
        }
        
        if (dateData.Count >= 2)
        {
            var firstCount = dateData.First().Count;
            var lastCount = dateData.Last().Count;
            var percentChange = firstCount > 0 ? (double)(lastCount - firstCount) / firstCount * 100 : 0;
            
            Console.WriteLine($"\nTrend Analysis: {(percentChange > 0 ? "Increasing" : percentChange < 0 ? "Decreasing" : "Stable")} " +
                              $"({Math.Abs(percentChange):F1}% {(percentChange > 0 ? "increase" : "decrease")})");
        }
        
        Console.WriteLine("====================================================");
    }
}
