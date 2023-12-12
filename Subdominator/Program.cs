using Nager.PublicSuffix;
using System.Diagnostics;
using System.CommandLine;

namespace Subdominator;

public class Program
{
    private static readonly object _fileLock = new();

    public static async Task Main(string[] args)
    {
        var rootCommand = new RootCommand("A subdomain takover detection tool for cool kids");

        var optionDomain = new Option<string>(new[] { "-d", "--domain" }, "A single domain to check");
        var optionList = new Option<string>(new[] { "-l", "--list" }, "A list of domains to check (line delimited)");
        var optionOutput = new Option<string>(new[] { "-o", "--output" }, "Output subdomains to a file");
        var optionThreads = new Option<int>(new[] { "-t", "--threads" }, () => 50, "Number of domains to check at once");
        var optionVerbose = new Option<bool>(new[] { "-v", "--verbose" }, "Print extra information");

        rootCommand.AddOption(optionDomain);
        rootCommand.AddOption(optionList);
        rootCommand.AddOption(optionOutput);
        rootCommand.AddOption(optionThreads);
        rootCommand.AddOption(optionVerbose);

        rootCommand.SetHandler(async (string domain, string domainsFile, string outputFile, int threads, bool verbose) =>
        {
            var options = new Options
            {
                Domain = domain,
                DomainsFile = domainsFile,
                OutputFile = outputFile,
                Threads = threads,
                Verbose = verbose
            };
            await RunSubdominator(options);
        }, optionDomain, optionList, optionOutput, optionThreads, optionVerbose);

        // Parse the incoming args and invoke the handler
        await rootCommand.InvokeAsync(args);
    }

    static async Task RunSubdominator(Options o)
    {
        // Get domain(s) from the options
        var rawDomains = new List<string>();
        if (!string.IsNullOrEmpty(o.DomainsFile))
        {
            string file = o.DomainsFile;
            rawDomains = (await File.ReadAllLinesAsync(file)).ToList();
        }
        else if (!string.IsNullOrEmpty(o.Domain))
        {
            rawDomains.Add(o.Domain);
        }
        else
        {
            throw new Exception("A domain (-d) or file (-l) must be specified.");
        }

        // Define maximum concurrent tasks
        int maxConcurrentTasks = o.Threads;
        bool verbose = o.Verbose;
        bool isAnyVulnerable = false;

        // Pre-check domains passed in and filter any that are invalid
        var domains = FilterAndNormalizeDomains(rawDomains);

        // Pre-load fingerprints to memory
        var hijackChecker = new SubdomainHijack();
        await hijackChecker.GetFingerprintsAsync();

        // Do the things
        var stopwatch = new Stopwatch();
        stopwatch.Start();

        int completedTasks = 0;
        var updateInterval = TimeSpan.FromSeconds(10);

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
            var isVulnerable = await CheckAndLogDomain(hijackChecker, domain, o.OutputFile, verbose);
            if(isVulnerable)
            {
                isAnyVulnerable = true;
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
        Console.WriteLine("Done in " + stopwatch.Elapsed.TotalSeconds + "s");

        // Exit non-zero if we have a takeover, for the DevOps folks
        if (isAnyVulnerable)
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

    static IEnumerable<string> FilterAndNormalizeDomains(List<string> domains, bool verbose = false)
    {
        var domainParser = new DomainParser(new WebTldRuleProvider("https://raw.githubusercontent.com/Stratus-Security/Subdominator/master/Subdominator/public_suffix_list.dat"));

        // Normalize domains and check validity
        var normalizedDomains = domains
            .Select(domain => domain.Replace("http://", "").Replace("https://", "").TrimEnd('/'))
            .Select(domain => new { Original = domain, IsValid = domainParser.IsValidDomain(domain) })
            .ToList();

        // Count and report removed domains
        if (verbose)
        {
            var removedDomains = normalizedDomains.Count(d => !d.IsValid);
            if (removedDomains > 0)
            {
                Console.WriteLine($"Removed {removedDomains} invalid domains.");
            }
        }

        // Return only valid domains
        return normalizedDomains.Where(d => d.IsValid).Select(d => d.Original);
    }

    static async Task<bool> CheckAndLogDomain(SubdomainHijack hijackChecker, string domain, string outputFile, bool verbose = false)
    {
        bool isFound = false;
        try
        {
            var (isVulnerable, fingerprint, cnames) = await hijackChecker.IsDomainVulnerable(domain);
            if (isVulnerable || verbose)
            {
                if (isVulnerable)
                {
                    isFound = true;
                }
                var fingerPrintName = fingerprint == null ? "-" : fingerprint.Service;

                // Build the output string
                var output = $"[{fingerPrintName}] {domain} - CNAME: {string.Join(", ", cnames)}";

                // Thread-safe console print and append to results file
                lock (_fileLock)
                {
                    Console.Write("[");
                    Console.ForegroundColor = isVulnerable ? ConsoleColor.Red : ConsoleColor.Green;
                    Console.Write(fingerPrintName);
                    Console.ResetColor();
                    Console.Write($"] {domain} - CNAME: {string.Join(", ", cnames)}" + Environment.NewLine);

                    if (!string.IsNullOrWhiteSpace(outputFile))
                    {
                        File.AppendAllText(outputFile, output + Environment.NewLine);
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