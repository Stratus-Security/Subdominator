using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Subdominator.Tests;

[TestClass]
public class CoverageTests
{
    private HttpClient _http;

    [TestInitialize]
    public async Task Setup()
    {
        _http = new HttpClient();
        _http.DefaultRequestHeaders.UserAgent.Clear();
        _http.DefaultRequestHeaders.UserAgent.Add(new System.Net.Http.Headers.ProductInfoHeaderValue("Subdominator", "1"));
    }

    [TestMethod]
    public async Task TestDnsCoverage()
    {

    }

    [TestMethod]
    public async Task TestDomainCoverage()
    {
        var myFingerprints = (await new SubdomainHijack().GetFingerprintsAsync()).ToList();
        var canITakeOverFingerprints = await GetCanITakeOverXyzFingerprints();
        var subdoverFingerprints = await GetSubdoverFingerprints();
        var subjackFingerprints = await GetSubjackFingerprints();
        var dnsReaperFingerprints = await GetDnsReaperFingerprints();
        var echoCipherFingerprints = await GetEchoCipherFingerprints();

        // Make sure we got them all correctly
        Assert.IsTrue(myFingerprints.Any());
        Assert.IsTrue(canITakeOverFingerprints.Any());
        Assert.IsTrue(subdoverFingerprints.Any());
        Assert.IsTrue(subjackFingerprints.Any());
        Assert.IsTrue(dnsReaperFingerprints.Any());
        Assert.IsTrue(echoCipherFingerprints.Any());

        // Make sure there's no "Not vulnerable" services
        Assert.IsFalse(myFingerprints.Any(f => f.Status.ToLower() == "not vulnerable"));
        Assert.IsFalse(canITakeOverFingerprints.Any(f => f.Status.ToLower() == "not vulnerable"));
        Assert.IsFalse(subdoverFingerprints.Any(f => f.Status.ToLower() == "not vulnerable"));
        Assert.IsFalse(subjackFingerprints.Any(f => f.Status?.ToLower() == "not vulnerable"));
        Assert.IsFalse(dnsReaperFingerprints.Any(f => f.Status.ToLower() == "not vulnerable"));
        Assert.IsFalse(echoCipherFingerprints.Any(f => f.Status.ToLower() == "not vulnerable"));

        // Generic function to normalize service names
        static string normalizeServiceName(string name) => name.ToLowerInvariant()
            .Replace(" ", "").Replace("_", "").Replace("-", "").Replace(".org", "")
            .Replace(".io", "").Replace(".com", "").Replace(".net", "");

        // Define mappings for remaining service name differences
        var mappings = new Dictionary<string, List<string>>
        {
            {"cargocollective", new(){ "cargo" }},
            {"smugsmug", new(){ "smugmug" }},
            {"smartjobboard", new(){ "smartjob", "mysmartjobboard" }},
            {"short", new(){ "shortio" }},
            {"aws/s3", new(){ "s3bucket", "amazonaws" }},
            {"surge.sh", new(){ "surge" }},
            {"microsoftazure", new(){ "azure" }},
            {"aws/elasticbeanstalk", new(){ "elasticbeanstalkawsservice", "elasticbeanstalk" }},
            {"airee.ru", new(){ "aireeru" }},
            {"wordpress", new(){ "wordpresscomcname" }},
            {"activecampaign", new(){ "activecompaign" }},
            {"campaignmonitor", new(){ "compaignmonitor" } },
            {"github", new(){ "githubpages" } },
            {"launchrock", new(){ "launchrockcname" } },
            {"vend", new(){ "vendhq" } },
            {"zohoformsindia", new(){ "zohoformsin" } }
        };

        // Some tools have invalid fingerprints that aren't possible to take over anymore
        var invalidFingerprints = new List<string>()
        {
            "cloudfront",
            "feedpress",
            "statuspage",
            "freshdesk",
            "hubspot",
            "kinsta",
            "desk"
        };

        var dnsFingerprints = new List<string>()
        {
            "000domains",
            "awsns",
            "bizland",
            "brandpad",
            "dnsmadeeasy",
            "dnssimple",
            "domain",
            "dotster",
            "googlecloud",
            "hostinger",
            "hurricaneelectric",
            "linode",
            "mediatemplate",
            "name", // name.com
            "nsone",
            "reg",
            "tierranet",
            "wordpresscomns"
        };

        // Function to apply mappings to service names
        string applyMappings(string serviceName)
        {
            var normalizedServiceName = normalizeServiceName(serviceName);
            foreach (var mapping in mappings)
            {
                if (mapping.Value.Contains(normalizedServiceName))
                {
                    return mapping.Key;  // Return the key if the normalized name is in the value list
                }
            }
            return normalizedServiceName;  // Return the normalized name if no mapping is found
        }

        // Dictionary to hold normalized service names and their sources
        var serviceSources = new Dictionary<string, List<string>>();

        // Helper method to add services to the dictionary
        void AddServices(IEnumerable<Fingerprint> fingerprints, string source)
        {
            foreach (var fp in fingerprints)
            {
                var mappedService = applyMappings(fp.Service);
                if (!invalidFingerprints.Contains(mappedService) && !dnsFingerprints.Contains(mappedService))
                {
                    if (!serviceSources.ContainsKey(mappedService))
                    {
                        serviceSources[mappedService] = new List<string>();
                    }
                    serviceSources[mappedService].Add(source);
                }
            }
        }

        // Add services from each source
        AddServices(canITakeOverFingerprints, "CanITakeOver");
        AddServices(subdoverFingerprints, "Subdover");
        AddServices(subjackFingerprints, "Subjack");
        AddServices(dnsReaperFingerprints, "DNSReaper");
        AddServices(echoCipherFingerprints, "EchoCipher");

        // Normalized services from your fingerprints
        var myNormalizedServices = myFingerprints.Select(fp => applyMappings(fp.Service)).ToHashSet();

        // Find missing services
        var missingFingerprints = serviceSources.Keys.Except(myNormalizedServices).ToList();

        // Filter fingerprints to exclude invalid and DNS services before counting
        int countValidFingerprints(IEnumerable<Fingerprint> fingerprints) =>
            fingerprints.Count(fp => !invalidFingerprints.Contains(applyMappings(fp.Service))
                                  && !dnsFingerprints.Contains(applyMappings(fp.Service)));

        // Calculate number of fingerprints for each tool
        var myFingerprintCount = countValidFingerprints(myFingerprints);
        var canITakeOverCount = countValidFingerprints(canITakeOverFingerprints);
        var subdoverCount = countValidFingerprints(subdoverFingerprints);
        var subjackCount = countValidFingerprints(subjackFingerprints);
        var dnsReaperCount = countValidFingerprints(dnsReaperFingerprints);
        var echoCipherCount = countValidFingerprints(echoCipherFingerprints);

        // Calculate crossover counts for each set of fingerprints
        var calculateCrossoverCount = new Func<IEnumerable<Fingerprint>, int>(fingerprints =>
            fingerprints.Count(fp => myNormalizedServices.Contains(applyMappings(fp.Service))));

        var canITakeOverCrossoverCount = calculateCrossoverCount(canITakeOverFingerprints);
        var subdoverCrossoverCount = calculateCrossoverCount(subdoverFingerprints);
        var subjackCrossoverCount = calculateCrossoverCount(subjackFingerprints);
        var dnsReaperCrossoverCount = calculateCrossoverCount(dnsReaperFingerprints);
        var echoCipherCrossoverCount = calculateCrossoverCount(echoCipherFingerprints);

        // Print results
        Console.WriteLine($"Custom Fingerprints:       {myFingerprintCount}, Crossover: {myFingerprintCount}");
        Console.WriteLine($"CanITakeOver Fingerprints: {canITakeOverCount}, Crossover: {canITakeOverCrossoverCount}");
        Console.WriteLine($"Subdover Fingerprints:     {subdoverCount}, Crossover: {subdoverCrossoverCount}");
        Console.WriteLine($"Subjack Fingerprints:      {subjackCount}, Crossover: {subjackCrossoverCount}");
        Console.WriteLine($"DNS Reaper Fingerprints:   {dnsReaperCount}, Crossover: {dnsReaperCrossoverCount}");
        Console.WriteLine($"EchoCipher Fingerprints:   {echoCipherCount}, Crossover: {echoCipherCrossoverCount}");

        // Print missing services, if any
        if (missingFingerprints.Any())
        {
            Console.WriteLine("These services are not found in the custom fingerprints: ");
            foreach (var service in missingFingerprints)
            {
                var sources = string.Join(", ", serviceSources[service]);
                Console.WriteLine($"\t{service} (found in {sources})");
            }
        }
        else
        {
            Console.WriteLine("Subdominator has complete coverage!");
        }
    }

    private async Task<List<Fingerprint>> GetCanITakeOverXyzFingerprints()
    {
        var canitakeoverxyzFingerprintJson = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json";
        var fingerprintsData = await _http.GetStringAsync(canitakeoverxyzFingerprintJson);
        return JsonSerializer.Deserialize<List<Fingerprint>>(fingerprintsData)?
            .Where(f => f.Status.ToLower() != "not vulnerable").ToList() ?? new List<Fingerprint>();
    }

    private async Task<List<Fingerprint>> GetSubdoverFingerprints()
    {
        var subdoverFingerprintsPy = "https://raw.githubusercontent.com/PushpenderIndia/subdover/master/src/fingerprints.py";
        var pythonFileContent = await _http.GetStringAsync(subdoverFingerprintsPy);

        // Parse out the fingerprints
        const string startIndicator = "fingerprints_list = [";
        const string endIndicator = "];";

        int startIndex = pythonFileContent.IndexOf(startIndicator);
        if (startIndex == -1)
        {
            throw new Exception("Unable to parse Subdover fingerprints, start not found"); // Start indicator not found, throw
        }
        startIndex += startIndicator.Length - 1; // Adjust to include the opening bracket '['

        // Now we need to parse the json into objects following our structure
        var subdoverJson = pythonFileContent[startIndex..];

        // Regular expression to remove Python-style comments
        string jsonCompatibleString = Regex.Replace(subdoverJson.Replace("&#8217;", "'"), @"#.*", "")
            .Replace("\r", "").Replace("\n", "");

        // Grab their array of arrays as objects because I'm too lazy to add classes for each provider
        var options = new JsonSerializerOptions { AllowTrailingCommas = true };
        var rawFingerprints = JsonSerializer.Deserialize<List<List<object>>>(jsonCompatibleString, options);
        if (rawFingerprints == null)
        {
            return new List<Fingerprint>();
        }

        var fingerprints = new List<Fingerprint>();
        foreach (var rawFingerprint in rawFingerprints)
        {
            var fingerprint = new Fingerprint
            {
                Service = rawFingerprint[0].ToString(),
                Status = rawFingerprint[1].ToString(),
                Cnames = rawFingerprint[2] is JsonElement jsonElement && jsonElement.ValueKind == JsonValueKind.Array
                         ? jsonElement.EnumerateArray().Select(element => element.GetString()).ToList()
                         : new List<string>(),
                FingerprintTexts = new List<string> { rawFingerprint[3].ToString() },
                Vulnerable = true
            };

            fingerprints.Add(fingerprint);
        }

        return fingerprints.Where(f => f.Status.ToLower() != "not vulnerable").ToList();
    }

    private async Task<List<Fingerprint>> GetSubjackFingerprints()
    {
        var subjackFingerprintJson = "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json";
        var jsonContent = await _http.GetStringAsync(subjackFingerprintJson);

        return JsonSerializer.Deserialize<List<Fingerprint>>(jsonContent) ?? new List<Fingerprint>();
    }

    // For DNS Reaper we are being a little cheeky and just pulling the signatures repo to check file names
    private async Task<List<Fingerprint>> GetDnsReaperFingerprints()
    {
        var dnsReaperSignatures = "https://api.github.com/repos/punk-security/dnsReaper/contents/signatures?ref=main";

        var response = await _http.GetStringAsync(dnsReaperSignatures);

        var fileEntries = JsonSerializer.Deserialize<List<GitFileEntry>>(response, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        if (fileEntries == null)
        {
            return new List<Fingerprint>();
        }

        var fingerprints = new List<Fingerprint>();
        foreach (var fileEntry in fileEntries)
        {
            if (fileEntry.Type == "file" && !fileEntry.Name.StartsWith("_") && fileEntry.Name.EndsWith(".py"))
            {
                var serviceName = fileEntry.Name.Replace(".py", ""); // Removing the .py extension
                var fingerprint = new Fingerprint
                {
                    Service = serviceName,
                    Cnames = new List<string>(),
                    FingerprintTexts = new List<string>(),
                    HttpStatus = null,
                    Nxdomain = false,
                    Status = "Vulnerable",
                    Vulnerable = true
                };

                fingerprints.Add(fingerprint);
            }
        }

        return fingerprints;
    }

    private async Task<List<Fingerprint>> GetEchoCipherFingerprints()
    {
        var jsonUrl = "https://raw.githubusercontent.com/Echocipher/Subdomain-Takeover/master/providers.json";
        var response = await _http.GetStringAsync(jsonUrl);

        var rawFingerprints = JsonSerializer.Deserialize<List<EchoCipherFingerprint>>(response, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (rawFingerprints == null)
        {
            return new List<Fingerprint>();
        }

        var echoCipherFingerprints = new List<Fingerprint>();
        foreach (var rawFingerprint in rawFingerprints)
        {
            var fingerprint = new Fingerprint
            {
                Service = rawFingerprint.Name,
                Cnames = rawFingerprint.Cname,
                FingerprintTexts = rawFingerprint.Response,
                HttpStatus = null,
                Nxdomain = false,
                Status = "Vulnerable",
                Vulnerable = true
            };

            echoCipherFingerprints.Add(fingerprint);
        }

        return echoCipherFingerprints;
    }

    private class GitFileEntry
    {
        public string Name { get; set; }
        public string Type { get; set; }
    }

    private class EchoCipherFingerprint
    {
        public string Name { get; set; }
        public List<string> Cname { get; set; }
        public List<string> Response { get; set; }
    }
}
