using Nager.PublicSuffix;
using System.Diagnostics;
using System.CommandLine;
using Subdominator.Models;
using System.Text;
using System.Globalization;
using CsvHelper;
using CsvHelper.Configuration;
using Nager.PublicSuffix.RuleProviders;
using Nager.PublicSuffix.RuleProviders.CacheProviders;
using Microsoft.Extensions.Configuration;
using System.Text.Json;
using System.Collections.Concurrent;
using Subdominator.Database;

namespace Subdominator;

public class Program
{
    private static readonly object _fileLock = new();
    private static StreamWriter? _outputFileWriter = null;
    private static readonly string _version = "v1.71";

    public static async Task Main(string[] args = null)
    {
        Console.OutputEncoding = Encoding.UTF8;

        // Define the command line options
        // Note: For options that don't match the flag (e.g. --domain == Options.Domain), use name property to map to the correct property
        var command = new RootCommand("A subdomain takeover detection tool for cool kids")
        {
            new Option<string>(["-d", "--domain"], "A single domain to check"),
            new Option<string>(["-l", "--list"], "A list of domains to check (line delimited)") { Name = "DomainsFile" }, 
            new Option<string>(["-o", "--output"], "Output subdomains to a file") { Name = "OutputFile" },
            new Option<int>(["-t", "--threads"], () => 50, "Number of domains to check at once"),
            new Option<bool>(["-v", "--verbose"], "Print extra information"),
            new Option<bool>(["-q", "--quiet"], "Quiet mode: Only print found results"),
            new Option<string>(["-c", "--csv"], "Heading or column index to parse for CSV file. Forces -l to read as CSV instead of line-delimited") { Name = "CsvHeading" },
            new Option<bool>(["-eu", "--exclude-unlikely"], "Exclude unlikely (edge-case) fingerprints"),
            new Option<bool>(["--validate"], "Validate the takeovers are exploitable (where possible)"),
            new Option<bool>(["--adaptive-threads"], "Automatically adjust thread count based on system resources") { Name = "AdaptiveThreads" },
            new Option<string>(["--previous-results"], "Path to previous results file for comparison") { Name = "PreviousResults" },
            new Option<bool>(["--auto-update"], "Automatically update fingerprint database") { Name = "AutoUpdate" },
            new Option<string>(["--risk-level"], () => "all", "Filter results by risk level (low, medium, high, critical, all)") { Name = "RiskLevel" },
            new Option<string>(["--service-filter"], "Filter results by service name (e.g. 'AWS', 'Azure')") { Name = "ServiceFilter" },
            new Option<bool>(["-i", "--interactive"], "Interactive mode: prompt for action when finding vulnerabilities") { Name = "Interactive" },
            
            // Database and trend analysis options
            new Option<bool>(["--no-database"], "Disable storing results in SQLite database") { Name = "UseDatabase", Invert = true },
            new Option<string>(["--db-path"], () => "vulnerabilities.db", "Path to the SQLite database file") { Name = "DatabasePath" },
            new Option<bool>(["--trend-report"], "Generate HTML trend report after scanning") { Name = "GenerateTrendReport" },
            new Option<string>(["--trend-report-path"], () => "trend_report.html", "Path to save the trend report HTML file") { Name = "TrendReportPath" },
            new Option<bool>(["--trend-summary"], "Print trend analysis summary after scanning") { Name = "PrintTrendSummary" }
        };

        command.SetHandler(async (options) =>
        {
            await RunSubdominator(options);
        }, new OptionsBinder([.. command.Options]));
            
        // Parse the incoming args and invoke the handler
        await command.InvokeAsync(args);
    }

    public static async Task RunSubdominator(Options o)
    {
        // Initialize database if enabled
        VulnerabilityDatabase database = null;
        string scanId = Guid.NewGuid().ToString();
        DateTime scanStartTime = DateTime.UtcNow;
        
        if (o.UseDatabase)
        {
            try
            {
                database = new VulnerabilityDatabase(o.DatabasePath);
                if (!o.Quiet)
                {
                    Console.WriteLine($"Using vulnerability database: {Path.GetFullPath(o.DatabasePath)}");
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"Warning: Failed to initialize database: {ex.Message}");
                Console.WriteLine("Continuing without database functionality...");
                Console.ResetColor();
            }
        }
        // Print banner!
        if (!o.Quiet)
        {
            Console.WriteLine(@$"

 _____       _         _                 _             _             
/  ___|     | |       | |               (_)           | |            
\ `--. _   _| |__   __| | ___  _ __ ___  _ _ __   __ _| |_ ___  _ __ 
 `--. \ | | | '_ \ / _` |/ _ \| '_ ` _ \| | '_ \ / _` | __/ _ \| '__|
/\__/ / |_| | |_) | (_| | (_) | | | | | | | | | | (_| | || (_) | |   
\____/ \__,_|_.__/ \__,_|\___/|_| |_| |_|_|_| |_|\__,_|\__\___/|_|   
                    {_version} | stratussecurity.com
");
        }

        // Get domain(s) from the options
        var rawDomains = new List<string>();
        if (!string.IsNullOrEmpty(o.DomainsFile))
        {
            string file = o.DomainsFile;
            if (string.IsNullOrEmpty(o.CsvHeading))
            {
                rawDomains = [.. (await File.ReadAllLinesAsync(file))];
            }
            else // CSV input
            {
                try
                {
                    using var reader = new StreamReader(file);
                    using var csv = new CsvReader(reader, CultureInfo.InvariantCulture);
                    var config = new CsvConfiguration(CultureInfo.InvariantCulture)
                    {
                        PrepareHeaderForMatch = args => args.Header.Trim(),
                    };
                    csv.Read();
                    csv.ReadHeader();
                    while (csv.Read())
                    {
                        string domain;
                        if (int.TryParse(o.CsvHeading, out int columnIndex))
                        {
                            domain = csv.GetField<string>(columnIndex);
                        }
                        else
                        {
                            domain = csv.GetField<string>(o.CsvHeading);
                        }
                        rawDomains.Add(domain);
                    }
                }
                catch (CsvHelper.MissingFieldException)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"The CSV ({file}) is missing the specified heading! ({o.CsvHeading})");
                    Console.ResetColor();
                    return;
                }
            }
        }
        else if (!string.IsNullOrEmpty(o.Domain))
        {
            rawDomains.Add(o.Domain);
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("A domain (-d) or file (-l) must be specified!");
            Console.ResetColor();
            return;
        }

        // Define maximum concurrent tasks
        int maxConcurrentTasks = o.Threads;
        
        // Use adaptive threading if enabled
        if (o.AdaptiveThreads)
        {
            maxConcurrentTasks = DetermineOptimalThreadCount();
            if (!o.Quiet)
            {
                Console.WriteLine($"Using adaptive thread count: {maxConcurrentTasks}");
            }
        }
        
        var vulnerableCount = 0;

        // Pre-check domains passed in and filter any that are invalid
        var domains = await FilterAndNormalizeDomains(rawDomains, o.Quiet);

        // Load previous results if specified for comparison
        Dictionary<string, TakeoverResult> previousResults = new();
        if (!string.IsNullOrEmpty(o.PreviousResults) && File.Exists(o.PreviousResults))
        {
            try
            {
                var previousResultsJson = await File.ReadAllTextAsync(o.PreviousResults);
                previousResults = JsonSerializer.Deserialize<Dictionary<string, TakeoverResult>>(previousResultsJson) ?? new();
                if (!o.Quiet)
                {
                    Console.WriteLine($"Loaded {previousResults.Count} previous results for comparison");
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"Warning: Failed to load previous results: {ex.Message}");
                Console.ResetColor();
            }
        }

        // Current results dictionary for saving
        var currentResults = new ConcurrentDictionary<string, TakeoverResult>();

        // Pre-load fingerprints to memory
        var hijackChecker = new SubdomainHijack();
        await hijackChecker.GetFingerprintsAsync(o.ExcludeUnlikely, o.AutoUpdate);

        // Do the things
        var stopwatch = new Stopwatch();
        stopwatch.Start();

        int completedTasks = 0;
        var updateInterval = TimeSpan.FromSeconds(60);

        using var cts = new CancellationTokenSource();
        var updateTask = PeriodicUpdateAsync(updateInterval, () =>
        {
            // Skip the first print since it's 0 anyway
            if (!o.Quiet && completedTasks != 0)
            {
                var elapsed = stopwatch.Elapsed;
                var rate = completedTasks / elapsed.TotalSeconds;
                Console.WriteLine($"{completedTasks}/{domains.Count()} domains processed. Average rate: {rate:F2} domains/sec");
            }
        }, cts.Token);

        // Set up output file if specified
        if (!string.IsNullOrWhiteSpace(o.OutputFile))
        {
            _outputFileWriter = new StreamWriter(o.OutputFile, append: true)
            {
                AutoFlush = true
            };
        }

        await Parallel.ForEachAsync(domains, new ParallelOptions { MaxDegreeOfParallelism = maxConcurrentTasks }, async (domain, cancellationToken) =>
        {
            bool isNew = !previousResults.ContainsKey(domain);
            var result = await hijackChecker.IsDomainVulnerable(domain, o.Validate, o.AutoUpdate);
            
            // Store the result in the current results dictionary
            if (result.IsVulnerable)
            {
                currentResults.TryAdd(domain, result);
                
                // Save to database if enabled
                if (database != null)
                {
                    try
                    {
                        // Create and save vulnerability record
                        var vulnerabilityRecord = VulnerabilityRecord.FromTakeoverResult(result, domain, scanId);
                        database.SaveVulnerability(vulnerabilityRecord);
                    }
                    catch
                    {
                        // Ignore database errors during scanning to avoid interrupting the scan
                    }
                }
            }
            
            var isVulnerable = await CheckAndLogDomain(hijackChecker, domain, o.Validate, o.Verbose, o.Quiet, o.RiskLevel, isNew, o.ServiceFilter, o.Interactive);
            if(isVulnerable)
            {
                Interlocked.Increment(ref vulnerableCount);
            }
            Interlocked.Increment(ref completedTasks);
        });

        _outputFileWriter?.Close();
        stopwatch.Stop();
        cts.Cancel(); // Signal the update task to stop
        await updateTask; // Ensure the update task completes before finishing the program

        // Save results for future comparison if output file is specified
        if (!string.IsNullOrWhiteSpace(o.OutputFile) && currentResults.Any())
        {
            try
            {
                var resultsJson = JsonSerializer.Serialize(currentResults);
                string resultsJsonPath = Path.ChangeExtension(o.OutputFile, ".json");
                await File.WriteAllTextAsync(resultsJsonPath, resultsJson);
                if (!o.Quiet)
                {
                    Console.WriteLine($"Results saved to {resultsJsonPath} for future comparison");
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"Warning: Failed to save results for future comparison: {ex.Message}");
                Console.ResetColor();
            }
        }

        // One last output for clarity
        if (!o.Quiet)
        {
            var elapsed = stopwatch.Elapsed;
            var rate = completedTasks / elapsed.TotalSeconds;
            Console.WriteLine($"{completedTasks}/{domains.Count()} domains processed. Average rate: {rate:F2} domains/sec");
            Console.WriteLine($"Done in {stopwatch.Elapsed.TotalSeconds:N2}s! Subdominator found {vulnerableCount} vulnerable domains.");
        }

        // Save scan record to database and generate trend analysis if enabled
        if (database != null)
        {
            try
            {
                // Save scan record
                database.SaveScan(scanId, scanStartTime, domains.Count(), vulnerableCount, o);
                
                // Generate trend report if requested
                if (o.GenerateTrendReport)
                {
                    var analyzer = new TrendAnalyzer(database);
                    analyzer.GenerateTrendReport(o.TrendReportPath);
                }
                
                // Print trend summary if requested
                if (o.PrintTrendSummary)
                {
                    var analyzer = new TrendAnalyzer(database);
                    analyzer.PrintTrendSummary();
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"Warning: Database operation failed: {ex.Message}");
                Console.ResetColor();
            }
        }

        // Exit non-zero if we have a takeover, for the DevOps folks
        if (vulnerableCount > 0)
        {
            Environment.ExitCode = 1;
        }
    }

    static async Task PeriodicUpdateAsync(TimeSpan interval, Action action, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            action();
            try
            {
                await Task.Delay(interval, cancellationToken);
            }
            catch (TaskCanceledException)
            {
                break; // Exit loop if the task is canceled
            }
        }
    }
    
    static int DetermineOptimalThreadCount()
    {
        // Get available processors
        int processorCount = Environment.ProcessorCount;
        
        // Get available memory (this is approximate)
        long availableMemoryMB = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024);
        
        // Calculate thread count based on resources
        // Memory-based limit: Allow ~10MB per thread
        int memoryBasedThreads = (int)(availableMemoryMB / 10);
        
        // Processor-based limit: 2x processors is usually a good balance
        int processorBasedThreads = processorCount * 2;
        
        // Take the minimum of the two limits, but at least 5 threads and max 200
        return Math.Max(5, Math.Min(Math.Min(memoryBasedThreads, processorBasedThreads), 200));
    }

    static async Task<IEnumerable<string>> FilterAndNormalizeDomains(List<string> domains, bool quiet)
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(
            [
                new("Nager:PublicSuffix:DataUrl", "https://raw.githubusercontent.com/Stratus-Security/Subdominator/master/Subdominator/public_suffix_list.dat")
            ])
            .Build();
        var cacheProvider = new LocalFileSystemCacheProvider();
        var ruleProvider = new CachedHttpRuleProvider(cacheProvider, new HttpClient(), configuration);
        var domainParser = new DomainParser(ruleProvider);
        await ruleProvider.BuildAsync();

        // Normalize domains and check validity
        var normalizedDomains = domains
            .Select(domain => domain.Replace("http://", "").Replace("https://", "").TrimEnd('/'))
            .Select(domain => new { Original = domain, IsValid = domainParser.IsValidDomain(domain) })
            .ToList();

        // Count and report removed domains
        var removedDomains = normalizedDomains.Count(d => !d.IsValid);
        if (!quiet && removedDomains > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Removed {removedDomains} invalid domains.");
            Console.ResetColor();
        }

        // Return only valid domains
        return normalizedDomains.Where(d => d.IsValid).Select(d => d.Original);
    }

    private static string DetermineRiskLevel(TakeoverResult result)
    {
        // Logic to determine risk level based on service and other factors
        if (result.IsVerified)
        {
            return "Critical"; // Verified takeovers are critical
        }
        
        // High risk services that are commonly exploited
        string[] highRiskServices = new[] { "AWS/S3", "Github", "Heroku", "Azure", "Microsoft Azure" };
        
        // Medium risk services 
        string[] mediumRiskServices = new[] { "Fastly", "Netlify", "Shopify", "Vercel", "Webflow" };
        
        // Domain available is generally high risk
        if (result.MatchedLocation == MatchedLocation.DomainAvailable)
        {
            return "High";
        }
        
        if (result.Fingerprint != null)
        {
            // High risk services
            if (highRiskServices.Any(s => result.Fingerprint.Service.Contains(s, StringComparison.OrdinalIgnoreCase)))
            {
                return "High";
            }
            
            // Medium risk services
            if (mediumRiskServices.Any(s => result.Fingerprint.Service.Contains(s, StringComparison.OrdinalIgnoreCase)))
            {
                return "Medium";
            }
            
            // Edge cases are generally lower risk
            if (result.Fingerprint.Status.Equals("Edge case", StringComparison.OrdinalIgnoreCase))
            {
                return "Low";
            }
        }
        
        // Default to medium for other vulnerable services
        return "Medium";
    }

    static async Task<bool> CheckAndLogDomain(SubdomainHijack hijackChecker, string domain, bool validateResults, bool verbose, bool quiet, string riskLevel = "all", bool isNew = false, string serviceFilter = "", bool interactive = false)
    {
        bool isFound = false;
        try
        {
            var result = await hijackChecker.IsDomainVulnerable(domain, validateResults);
            if (result.IsVulnerable || verbose)
            {
                if (result.IsVulnerable)
                {
                    isFound = true;
                }
                var fingerPrintName = result.Fingerprint == null ? "-" : result.Fingerprint.Service;

                // Build the output string
                var output = $"{(result.IsVerified ? "✅ " : "")}[{fingerPrintName}] {domain} - CNAME: {string.Join(", ", result.CNAMES ?? [])}";

                // Show where we matched the takeover
                var locationString = "";
                if(result.MatchedRecord == MatchedRecord.CNAME)
                {
                    if(result.MatchedLocation != MatchedLocation.DomainAvailable ||
                        (result.MatchedLocation == MatchedLocation.DomainAvailable && result.CNAMES?.Any() == true)
                    )
                    {
                        locationString = $" - CNAME: {string.Join(", ", result.CNAMES ?? [])}";
                    }
                }
                else if(result.MatchedRecord == MatchedRecord.A)
                {
                    locationString = $" - A: {string.Join(", ", result.A ?? [])}";
                }
                else if (result.MatchedRecord == MatchedRecord.AAAA)
                {
                    locationString = $" - AAAA: {string.Join(", ", result.AAAA ?? [])}";
                }

                // Filter results by risk level if specified
                if (result.IsVulnerable && riskLevel != "all")
                {
                    var currentRisk = DetermineRiskLevel(result).ToLower();
                    if (currentRisk != riskLevel.ToLower())
                    {
                        // Skip this result if it doesn't match the requested risk level
                        return isFound;
                    }
                }
                
                // Filter by service name if specified
                if (result.IsVulnerable && !string.IsNullOrWhiteSpace(serviceFilter) && fingerPrintName != "-")
                {
                    if (!fingerPrintName.Contains(serviceFilter, StringComparison.OrdinalIgnoreCase))
                    {
                        // Skip this result if the service name doesn't contain the filter
                        return isFound;
                    }
                }

                // Thread-safe console print and append to results file
                lock (_fileLock)
                {
                    // Interactive mode handling for vulnerable domains
                    if (interactive && result.IsVulnerable)
                    {
                        // Display the vulnerability information
                        Console.WriteLine($"\n============ VULNERABILITY FOUND ============");
                        Console.WriteLine($"Domain: {domain}");
                        Console.WriteLine($"Service: {fingerPrintName}");
                        Console.WriteLine($"Risk Level: {DetermineRiskLevel(result)}");
                        Console.WriteLine($"Record Type: {result.MatchedRecord}");
                        Console.WriteLine($"Match Location: {result.MatchedLocation}");
                        
                        if (result.CNAMES?.Any() == true)
                            Console.WriteLine($"CNAME Records: {string.Join(", ", result.CNAMES)}");
                        if (result.A?.Any() == true)
                            Console.WriteLine($"A Records: {string.Join(", ", result.A)}");
                        if (result.AAAA?.Any() == true)
                            Console.WriteLine($"AAAA Records: {string.Join(", ", result.AAAA)}");
                            
                        Console.WriteLine("\nDo you want to (s)kip, (c)ontinue, (d)etails, or (q)uit? [c]: ");
                        
                        var key = Console.ReadKey(true).KeyChar.ToString().ToLower();
                        Console.WriteLine();
                        
                        switch (key)
                        {
                            case "s": // Skip this result
                                return isFound;
                            case "d": // Show more details
                                Console.WriteLine("\n======== VULNERABILITY DETAILS ========");
                                Console.WriteLine("What is Subdomain Takeover?");
                                Console.WriteLine("Subdomain takeover occurs when an attacker gains control of a subdomain of a target domain.");
                                Console.WriteLine("This typically happens when a DNS record points to a service that the attacker can claim.");
                                Console.WriteLine("\nPotential Impact:");
                                Console.WriteLine("- Hosting malicious content under your domain");
                                Console.WriteLine("- Stealing cookies and credentials");
                                Console.WriteLine("- Damaging brand reputation");
                                Console.WriteLine("\nRecommended Fix:");
                                Console.WriteLine("1. Remove the DNS record pointing to the vulnerable service");
                                Console.WriteLine("2. If the service is needed, reclaim it or set it up properly");
                                Console.WriteLine("3. Review all DNS records for similar issues");
                                Console.WriteLine("\nPress any key to continue...");
                                Console.ReadKey(true);
                                break;
                            case "q": // Quit the program
                                Console.WriteLine("Exiting program at user request.");
                                Environment.Exit(0);
                                break;
                            default: // Continue
                                // Just fall through to the normal output
                                break;
                        }
                    }
                    
                    // New finding indicator
                    if (isNew && result.IsVulnerable)
                    {
                        Console.Write("🆕 "); // New finding emoji indicator
                    }
                    
                    Console.Write($"{(result.IsVerified ? "✅ " : "")}[");
                    
                    // Set color based on risk level for vulnerable domains
                    if (result.IsVulnerable)
                    {
                        string risk = DetermineRiskLevel(result);
                        switch (risk.ToLower())
                        {
                            case "critical":
                                Console.ForegroundColor = ConsoleColor.DarkRed;
                                break;
                            case "high":
                                Console.ForegroundColor = ConsoleColor.Red;
                                break;
                            case "medium":
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                break;
                            case "low":
                                Console.ForegroundColor = ConsoleColor.Blue;
                                break;
                        }
                        
                        // Also display the risk level
                        Console.Write($"{risk}:{fingerPrintName}");
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write(fingerPrintName);
                    }
                    
                    Console.ResetColor();
                    Console.Write($"] {domain}" + locationString + Environment.NewLine);

                    if (_outputFileWriter != null)
                    {
                        _outputFileWriter.WriteLine(output + locationString);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.ToString());
        }
        return isFound;
    }
}