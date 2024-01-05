using Nager.PublicSuffix;
using System.Diagnostics;
using System.CommandLine;
using Subdominator.Models;
using System.Text;

namespace Subdominator;

public class Program
{
    private static readonly object _fileLock = new();

    public static async Task Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        var rootCommand = new RootCommand("A subdomain takover detection tool for cool kids");

        var optionDomain = new Option<string>(new[] { "-d", "--domain" }, "A single domain to check");
        var optionList = new Option<string>(new[] { "-l", "--list" }, "A list of domains to check (line delimited)");
        var optionOutput = new Option<string>(new[] { "-o", "--output" }, "Output subdomains to a file");
        var optionThreads = new Option<int>(new[] { "-t", "--threads" }, () => 50, "Number of domains to check at once");
        var optionVerbose = new Option<bool>(new[] { "-v", "--verbose" }, "Print extra information");
        var optionExcludeUnlikely = new Option<bool>(new[] { "-eu", "--exclude-unlikely" }, "Exclude unlikely (edge-case) fingerprints");
        var optionValidate = new Option<bool>(new[] { "--validate" }, "Validate the takeovers are exploitable (where possible)");

        rootCommand.AddOption(optionDomain);
        rootCommand.AddOption(optionList);
        rootCommand.AddOption(optionOutput);
        rootCommand.AddOption(optionThreads);
        rootCommand.AddOption(optionVerbose);
        rootCommand.AddOption(optionExcludeUnlikely);
        rootCommand.AddOption(optionValidate);

        rootCommand.SetHandler(async (string domain, string domainsFile, string outputFile, int threads, bool verbose, bool excludeUnlikely, bool validate) =>
        {
            var options = new Options
            {
                Domain = domain,
                DomainsFile = domainsFile,
                OutputFile = outputFile,
                Threads = threads,
                Verbose = verbose,
                ExcludeUnlikely = excludeUnlikely,
                Validate = validate
            };
            await RunSubdominator(options);
        }, optionDomain, optionList, optionOutput, optionThreads, optionVerbose, optionExcludeUnlikely, optionValidate);

        // Parse the incoming args and invoke the handler
        await rootCommand.InvokeAsync(args);
    }

    public static async Task RunSubdominator(Options o)
    {
        // Get domain(s) from the options
        var rawDomains = new List<string>();
        if (!string.IsNullOrEmpty(o.DomainsFile))
        {
            string file = o.DomainsFile;
            rawDomains = [.. (await File.ReadAllLinesAsync(file))];
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
        bool verbose = o.Verbose;
        var vulnerableCount = 0;

        // Pre-check domains passed in and filter any that are invalid
        var domains = FilterAndNormalizeDomains(rawDomains);

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
            if (completedTasks != 0)
            {
                var elapsed = stopwatch.Elapsed;
                var rate = completedTasks / elapsed.TotalSeconds;
                Console.WriteLine($"{completedTasks}/{domains.Count()} domains processed. Average rate: {rate:F2} domains/sec");
            }
        }, cts.Token);

        await Parallel.ForEachAsync(domains, new ParallelOptions { MaxDegreeOfParallelism = maxConcurrentTasks }, async (domain, cancellationToken) =>
        {
            var isVulnerable = await CheckAndLogDomain(hijackChecker, domain, o.OutputFile, o.Validate, verbose);
            if(isVulnerable)
            {
                Interlocked.Increment(ref vulnerableCount);
            }
            Interlocked.Increment(ref completedTasks);
        });

        stopwatch.Stop();
        cts.Cancel(); // Signal the update task to stop
        await updateTask; // Ensure the update task completes before finishing the program

        // One last output for clarity
        var elapsed = stopwatch.Elapsed;
        var rate = completedTasks / elapsed.TotalSeconds;
        Console.WriteLine($"{completedTasks}/{domains.Count()} domains processed. Average rate: {rate:F2} domains/sec");
        Console.WriteLine($"Done in {stopwatch.Elapsed.TotalSeconds:N2}s! Subdominator found {vulnerableCount} vulnerable domains.");

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

    static IEnumerable<string> FilterAndNormalizeDomains(List<string> domains)
    {
        var domainParser = new DomainParser(new WebTldRuleProvider("https://raw.githubusercontent.com/Stratus-Security/Subdominator/master/Subdominator/public_suffix_list.dat", new FileCacheProvider(cacheTimeToLive: TimeSpan.FromSeconds(0))));

        // Normalize domains and check validity
        var normalizedDomains = domains
            .Select(domain => domain.Replace("http://", "").Replace("https://", "").TrimEnd('/'))
            .Select(domain => new { Original = domain, IsValid = domainParser.IsValidDomain(domain) })
            .ToList();

        // Count and report removed domains
        var removedDomains = normalizedDomains.Count(d => !d.IsValid);
        if (removedDomains > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Removed {removedDomains} invalid domains.");
            Console.ResetColor();
        }

        // Return only valid domains
        return normalizedDomains.Where(d => d.IsValid).Select(d => d.Original);
    }

    static async Task<bool> CheckAndLogDomain(SubdomainHijack hijackChecker, string domain, string outputFile, bool validateResults, bool verbose = false)
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

                    if (!string.IsNullOrWhiteSpace(outputFile))
                    {
                        File.AppendAllText(outputFile, output + locationString + Environment.NewLine);
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