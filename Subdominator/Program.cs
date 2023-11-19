using Nager.PublicSuffix;
using System.Diagnostics;
using System.Runtime.Intrinsics.Arm;

namespace Subdominator;

internal class Program
{
    private static readonly object _fileLock = new();

    static async Task Main(string[] args)
    {
        var stopwatch1 = new Stopwatch();
        stopwatch1.Start();

        // Define maximum concurrent tasks
        int maxConcurrentTasks = 50;
        bool verbose = false;

        // Get domains
        var rawDomains = await File.ReadAllLinesAsync("subs.txt");

        // Pre-check domains passed in and filter any that are invalid
        var domains = FilterAndNormalizeDomains(rawDomains).ToList();

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
            var elapsed = stopwatch.Elapsed;
            var rate = completedTasks / elapsed.TotalSeconds;
            Console.WriteLine($"{completedTasks}/{domains.Count} domains processed. Average rate: {rate:F2} domains/sec");
        }, cts.Token);

        await Parallel.ForEachAsync(domains, new ParallelOptions { MaxDegreeOfParallelism = maxConcurrentTasks }, async (domain, cancellationToken) =>
        {
            await CheckAndLogDomain(hijackChecker, domain, verbose);
            Interlocked.Increment(ref completedTasks);
        });

        stopwatch.Stop();
        cts.Cancel(); // Signal the update task to stop
        await updateTask; // Ensure the update task completes before finishing the program

        stopwatch1.Stop();
        Console.WriteLine("Done! Running took: " + stopwatch1.Elapsed.TotalSeconds);
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

    static IEnumerable<string> FilterAndNormalizeDomains(string[] domains, bool verbose = false)
    {
        var domainParser = new DomainParser(new FileTldRuleProvider("public_suffix_list.dat"));

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

    static async Task CheckAndLogDomain(SubdomainHijack hijackChecker, string domain, bool verbose = false)
    {
        try
        {
            var (isVulnerable, fingerprint, cnames) = await hijackChecker.IsDomainVulnerable(domain);
            if (isVulnerable || verbose)
            {
                var fingerPrintName = fingerprint == null ? "-" : fingerprint.Service;
                var cnameStr = isVulnerable && cnames != null ? $" - CNAMEs: {string.Join(", ", cnames)}" : string.Empty;

                // Build the output string
                var output = $"[{fingerPrintName}] {domain}{cnameStr}";

                // Thread-safe console print and append to results file
                lock (_fileLock)
                {
                    Console.Write("[");
                    Console.ForegroundColor = isVulnerable ? ConsoleColor.Red : ConsoleColor.Green;
                    Console.Write(fingerPrintName);
                    Console.ResetColor();
                    Console.Write($"] {domain}{cnameStr}\n");

                    File.AppendAllText("results.txt", output + Environment.NewLine);
                }
            }
        }
        catch (Exception ex) 
        {
            Console.WriteLine(ex.ToString());
        }
    }
}