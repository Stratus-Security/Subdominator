﻿using Nager.PublicSuffix;
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
            new Option<int>(["-t", "--threads"], () => 50, "Number of domains to check at once (0 or less uses default of 50)"),
            new Option<bool>(["-v", "--verbose"], "Print extra information"),
            new Option<bool>(["-q", "--quiet"], "Quiet mode: Only print found results"),
            new Option<string>(["-c", "--csv"], "Heading or column index to parse for CSV file. Forces -l to read as CSV instead of line-delimited") { Name = "CsvHeading" },
            new Option<bool>(["-eu", "--exclude-unlikely"], "Exclude unlikely (edge-case) fingerprints"),
            new Option<bool>(["--validate"], "Validate the takeovers are exploitable (where possible)")
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
        int maxConcurrentTasks = ValidateThreadCount(o.Threads);
        var vulnerableCount = 0;

        // Pre-check domains passed in and filter any that are invalid
        var domains = await FilterAndNormalizeDomains(rawDomains, o.Quiet);

        // Pre-load fingerprints to memory
        var hijackChecker = new SubdomainHijack();
        await hijackChecker.GetFingerprintsAsync(o.ExcludeUnlikely);

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
            var isVulnerable = await CheckAndLogDomain(hijackChecker, domain, o.Validate, o.Verbose, o.Quiet);
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

        // One last output for clarity
        if (!o.Quiet)
        {
            var elapsed = stopwatch.Elapsed;
            var rate = completedTasks / elapsed.TotalSeconds;
            Console.WriteLine($"{completedTasks}/{domains.Count()} domains processed. Average rate: {rate:F2} domains/sec");
            Console.WriteLine($"Done in {stopwatch.Elapsed.TotalSeconds:N2}s! Subdominator found {vulnerableCount} vulnerable domains.");
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

    static async Task<bool> CheckAndLogDomain(SubdomainHijack hijackChecker, string domain, bool validateResults, bool verbose, bool quiet)
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

                // Thread-safe console print and append to results file
                lock (_fileLock)
                {
                    Console.Write($"{(result.IsVerified ? "✅ " : "")}[");
                    Console.ForegroundColor = result.IsVulnerable ? ConsoleColor.Red : ConsoleColor.Green;
                    Console.Write(fingerPrintName);
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

    public static int ValidateThreadCount(int threads)
    {
        return threads > 0 ? threads : 50;
    }
}