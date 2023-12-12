using DnsClient;
using Nager.PublicSuffix;
using Subdominator.Models;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;

namespace Subdominator;

public class SubdomainHijack
{
    private readonly HttpClient _httpClient;
    private readonly HttpClient _httpClientNoRedirect;
    private readonly LookupClient _dnsClient;
    private List<Fingerprint> _fingerprints = new();
    private DomainParser _domainParser;

    // Some of the fingerprints are incorrectly labelled - these are all at least edge cases
    private HashSet<string> _overrides = new()
    {
        "Acquia",
        "Fastly",
        "Instapage", // https://github.com/EdOverflow/can-i-take-over-xyz/issues/349
        "Unbounce",
        "UserVoice", // Unsure - one confirmed report on snapchat
        "Zendesk"
    };

    // Some also have the wrong fingerprint >:(
    private Dictionary<string, List<string>> _fingerprintOverrides = new()
    {
        { "Acquia", new(){ "The site you are looking for could not be found.", "Web Site Not Found" } },
        { "Campaign Monitor", new(){ "Double check the URL or <a href=\"mailto:help@createsend.com" } },
        { "Cargo Collective", new(){ "If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel." } },
        { "Ghost", new(){ "The thing you were looking for is no longer here, or never was" } },
        { "Heroku", new(){ "herokucdn.com/error-pages/no-such-app.html" } },
        { "Instapage", new(){ "You've Discovered A Missing Link. Our Apologies!", "Looks Like You're Lost" } },
        { "Pantheon", new(){ "The gods are wise, but do not know of the site which you seek." } },
        { "Readthedocs", new(){ "is unknown to Read the Docs" } },
        { "Short.io", new(){ "This domain is not configured on Short.io" } },
        { "Wix", new(){ "Connect it to your Wix website in just a few easy steps", "Error ConnectYourDomain occurred" } },
        { "Ngrok", new(){ "ngrok.io not found" } },
        { "Wordpress", new(){ "Do you want to register " } }
    };
    
    // Extra cnames
    private Dictionary<string, List<string>> _cnameOverrides = new()
    {        
        { "Acquia", new(){ "acquia-test.co" } },
        { "Campaign Monitor", new(){ "createsend.com", "name.createsend.com" } },
        { "Canny", new(){ "cname.canny.io" } },
        { "Cargo Collective", new(){ "cargocollective.com", "subdomain.cargocollective.com" } },
        { "Fastly", new(){ "fastly.net" } },
        { "Frontify", new(){ "frontify.com" } },
        { "GetResponse", new(){ "gr8.com" } },
        { "Github", new() { "github.io" } },
        { "Heroku", new() { "herokuapp" } },
        { "Intercom", new() { "custom.intercom.help" } },
        { "Instapage", new(){ "pageserve.co", "secure.pageserve.co" } },
        { "Landingi", new() { "cname.landingi.com" } },
        { "Mashery", new() { "mashery.com" } },
        { "Microsoft Azure", new(){ "trafficmanager.net" } },
        { "Netlify", new() { "cname.netlify.app", "cname.netlify.com", "netlify.com", "netlify.app" } },
        { "Pantheon", new(){ "pantheonsite.io" } },
        { "Pingdom", new(){ "stats.pingdom.com" } },
        { "Readthedocs", new(){ "readthedocs.io" } },
        { "Shopify", new(){ "myshopify.com" } },
        { "Short.io", new(){ "cname.short.io" } },
        { "Smartling", new(){ "smartling.com" } },
        { "Smugsmug", new(){ "domains.smugmug.com" } },
        { "Tilda", new(){ "tilda.ws" } },
        { "Tumblr", new(){ "domains.tumblr.com" } },
        { "Unbounce", new(){ "unbouncepages.com" } },
        { "UserVoice", new(){ "uservoice.com" } },
        { "Webflow", new(){ "proxy.webflow.com", "proxy-ssl.webflow.com" } },
        { "Wix", new(){ "wixdns.net" } },
        { "Vercel", new(){ ".vercel.com", "cname.vercel-dns.com" } }
    };

    // At what point to I just make my own master list???
    private Dictionary<string, bool> _nxDomainOverride = new()
    {
        { "Smugsmug", true }
    };

    // We're fancy and support A/AAAA records
    private Dictionary<string, List<string>> _aOverrides = new()
    {
        { "Github", new(){ "185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153" } },
        { "Fastly", new(){ "151.101." } },
        { "Pantheon", new(){ "23.185.0." } },
        { "Vercel", new(){ "76.76.21.21" } }
    };

    private Dictionary<string, List<string>> _aaaaOverrides = new()
    {
        { "Github", new(){ "2606:50c0:8000::153", "2606:50c0:8001::153", "2606:50c0:8002::153", "2606:50c0:8003::153" } },
        { "Fastly", new(){ "2a04:4e42:" } },
        { "Pantheon", new(){ "2620:12a:" } }
    };

    public SubdomainHijack(int httpTimeout = 5)
    {
        // Magic fix for weird content-type encodings from sites like windows-874
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

        var handler = new HttpClientHandler
        {
            // Invalid SSL should be allowed
            ServerCertificateCustomValidationCallback = (message, certificate2, chain, errors) => true
        };
        _httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(httpTimeout) };

        // We want to ignore redirects when expecting something like a 301 and follow otherwise to get the best results
        handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, certificate2, chain, errors) => true,
            AllowAutoRedirect = false
        };
        _httpClientNoRedirect = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(httpTimeout) };

        _dnsClient = new LookupClient();

        _domainParser = new DomainParser(new WebTldRuleProvider("https://raw.githubusercontent.com/Stratus-Security/Subdominator/master/Subdominator/public_suffix_list.dat"));
    }

    public async Task<IEnumerable<Fingerprint>> GetFingerprintsAsync(bool excludeUnlikely, bool update = false)
    {
        // Don't reload if they're already cached in memory
        if (_fingerprints.Count == 0)
        {
            string filePath = "fingerprints.json";
            string customFilePath = "custom_fingerprints.json";
            string fingerprintsData, customFingerprintsData;

            try
            {
                // Check if the file exists locally
                if (!update && File.Exists(filePath))
                {
                    // Read from the file if it exists
                    fingerprintsData = await File.ReadAllTextAsync(filePath);
                }
                else
                {
                    // Download the file if it doesn't exist
                    var fingerprintsUrl = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json";
                    fingerprintsData = await _httpClient.GetStringAsync(fingerprintsUrl);

                    // Save the file locally for future use
                    await File.WriteAllTextAsync(filePath, fingerprintsData);
                }
                
                // We also have a custom fingerprints file to enhance coverage but still allow auto-updates from can-i-take-over-xyz
                if (!update && File.Exists(customFilePath))
                {
                    customFingerprintsData = await File.ReadAllTextAsync(customFilePath);
                }
                else
                {
                    var customFingerprintsUrl = "https://raw.githubusercontent.com/Stratus-Security/Subdominator/master/Subdominator/custom_fingerprints.json";
                    customFingerprintsData = await _httpClient.GetStringAsync(customFingerprintsUrl);

                    await File.WriteAllTextAsync(customFilePath, customFingerprintsData);
                }

                var options = new JsonSerializerOptions();
                var context = new JsonContext(options);

                // Deserialize the JSON data directly into a list of Fingerprint objects
                var fingerprints = JsonSerializer.Deserialize(fingerprintsData, context.ListFingerprint) ?? [];
                var customFingerprints = JsonSerializer.Deserialize(customFingerprintsData, context.ListFingerprint) ?? [];

                // Find and store appropriate fingerprints
                foreach (var fingerprint in fingerprints)
                {
                    // The override list contains edge cases that were incorrectly marked
                    if (_overrides.Contains(fingerprint.Service))
                    {
                        fingerprint.Status = "Edge case";
                    }

                    // Some of the fingerprints are wrong too :(
                    if (_fingerprintOverrides.ContainsKey(fingerprint.Service))
                    {
                        fingerprint.FingerprintTexts.AddRange(_fingerprintOverrides[fingerprint.Service]);
                    }

                    // Some of the cnames are missing so we fix
                    if (_cnameOverrides.ContainsKey(fingerprint.Service))
                    {
                        fingerprint.Cnames.AddRange(_cnameOverrides[fingerprint.Service]);
                    }

                    // Some nxdomain flags are wrong too ._.
                    if (_nxDomainOverride.ContainsKey(fingerprint.Service))
                    {
                        fingerprint.Nxdomain = _nxDomainOverride[fingerprint.Service];
                    }
                    
                    if (_aOverrides.ContainsKey(fingerprint.Service))
                    {
                        fingerprint.ARecords.AddRange(_aOverrides[fingerprint.Service]);
                    }

                    if (_aaaaOverrides.ContainsKey(fingerprint.Service))
                    {
                        fingerprint.AAAARecords.AddRange(_aaaaOverrides[fingerprint.Service]);
                    }

                    // Now ignore any non-vulnerable fingerprints
                    if (fingerprint.Status.ToLower() != "not vulnerable")
                    {
                        // Filter edge cases if requested
                        if(!(excludeUnlikely && fingerprint.Status.ToLower() == "edge case"))
                        {
                            _fingerprints.Add(fingerprint);
                        }
                    }
                }

                // Now iterate custom fingerprints. The custom list is used for completeness, so it should not override the original
                foreach(var fingerprint in customFingerprints)
                {
                    if (fingerprint.Status.ToLower() != "not vulnerable" && 
                        !_fingerprints.Any(f => f.Service.ToLower() == fingerprint.Service.ToLower())
                    )
                    {
                        // Filter edge cases if requested
                        if (!(excludeUnlikely && fingerprint.Status.ToLower() == "edge case"))
                        {
                            _fingerprints.Add(fingerprint);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error getting fingerprints! ({ex.Message})");
            }
        }

        return _fingerprints;
    }

    public async Task<(bool, Fingerprint?, List<string>? cnames)> IsDomainVulnerable(string domain, bool update = false)
    {
        var fingerprints = await GetFingerprintsAsync(update);

        // DNS Lookup
        var subdomainDns = await GetDnsForSubdomain(domain);

        // Before checking all the fingerprints, do the base check for expired domains
        if(subdomainDns.IsNxdomain)
        {
            // Check if the domain is registered
            if (subdomainDns.IsDomainRegistered == false)
            {
                return (true, new Fingerprint() { Service = "Domain Available" }, subdomainDns.Cnames);
            }
        }

        // Now check all the fingerprints
        foreach (var fingerprint in fingerprints)
        {
            if (await IsFingerprintVulnerable(fingerprint, subdomainDns, domain))
            {
                return (true, fingerprint, subdomainDns.Cnames);
            }
        }

        return (false, null, subdomainDns.Cnames);
    }

    // TODO: Return why records are vulnerable and what record matched
    public async Task<bool> IsFingerprintVulnerable(Fingerprint fingerprint, CnameResolutionResult dns, string domain)
    {
        var isCnameMatch = dns.Cnames.Any(r => fingerprint.Cnames.Any(r.Contains));
        var isAMatch = dns.A.Any(r => fingerprint.ARecords.Any(r.Contains));
        var isAaaaMatch = dns.AAAA.Any(r => fingerprint.AAAARecords.Any(r.Contains));

        // If we expected nxdomain, check the cname matches
        if (dns.IsNxdomain && fingerprint.Nxdomain)
        {
            // If any of the cnames, A or AAAA records from this fingerprint are in ours, match.
            // Note this is a loose match (hence contains) to remove the need for regexes
            if (isCnameMatch || isAMatch || isAaaaMatch)
            {
                return true;
            }
        }

        // Only check fingerprints if we have a (partial) match
        if (isCnameMatch || isAMatch || isAaaaMatch) 
        {
            var response = await HttpGet(domain, fingerprint.HttpStatus >= 300 && fingerprint.HttpStatus < 400);
            string responseBody = "";

            // If we didn't get NXDOMAIN'd
            if (response != null)
            {
                responseBody = await response.Content.ReadAsStringAsync();

                // Check if HTTP status matches the fingerprint
                if (fingerprint.HttpStatus.HasValue && (int)response.StatusCode == fingerprint.HttpStatus.Value)
                {
                    return true;
                }

                // Check response content is available and matches
                if (fingerprint.FingerprintTexts.Any() && !string.IsNullOrWhiteSpace(responseBody))
                {
                    foreach (var fingerprintMatch in fingerprint.FingerprintTexts)
                    {
                        if (!string.IsNullOrWhiteSpace(fingerprintMatch) && responseBody.Contains(fingerprintMatch))
                        {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    public async Task<CnameResolutionResult> GetDnsForSubdomain(string domain)
    {
        var result = new CnameResolutionResult();
        var visitedCnames = new HashSet<string>();

        try
        {
            await ResolveDns(domain, result, visitedCnames);
        }
        catch// (Exception ex)
        {
            // This is fine
            //throw new Exception($"Exception thrown trying to get cname records for {domain}! ({ex.Message})");
        }

        return result;
    }

    private async Task ResolveDns(string domain, CnameResolutionResult result, HashSet<string> visitedCnames)
    {
        const int maxRetries = 3; // Maximum number of retries
        int retryCount = 0;

        while (retryCount < maxRetries)
        {
            try
            {
                var cnameQueryResult = await _dnsClient.QueryAsync(domain, QueryType.CNAME);

                if (cnameQueryResult.Header.ResponseCode == DnsHeaderResponseCode.NotExistentDomain)
                {
                    result.IsNxdomain = true;
                    result.IsDomainRegistered = await CheckDomainRegistration(domain);
                    return;
                }
                else if (cnameQueryResult.HasError)
                {
                    throw new Exception("DNS query error >:(");
                }

                var cnameRecords = cnameQueryResult.Answers.CnameRecords().ToList();
                if (cnameRecords.Any())
                {
                    foreach (var cnameRecord in cnameRecords)
                    {
                        var cname = cnameRecord.CanonicalName.Value;

                        // Check for loops
                        if (visitedCnames.Contains(cname))
                        {
                            // Loop detected, move on
                            return;
                        }

                        visitedCnames.Add(cname);
                        result.Cnames.Add(cname);

                        // Recursively resolve the current CNAME
                        await ResolveDns(cname, result, visitedCnames);
                    }
                }
                else
                {
                    // Parallel queries for A and AAAA records
                    var aTask = _dnsClient.QueryAsync(domain, QueryType.A);
                    var aaaaTask = _dnsClient.QueryAsync(domain, QueryType.AAAA);
                    await Task.WhenAll(aTask, aaaaTask);

                    var aQueryResult = aTask.Result;
                    foreach (var aRecord in aQueryResult.Answers.ARecords())
                    {
                        result.A.Add(aRecord.Address.ToString());
                    }

                    var aaaaQueryResult = aaaaTask.Result;
                    foreach (var aaaaRecord in aaaaQueryResult.Answers.AaaaRecords())
                    {
                        result.AAAA.Add(aaaaRecord.Address.ToString());
                    }
                }

                // If we reach this point, it means the operation was successful
                break;
            }
            catch //(Exception ex)
            {
                retryCount++;
                if (retryCount >= maxRetries)
                {
                    // This is fine, almost always a bad record but we retry just in case
                    //Console.WriteLine($"Exception thrown trying to get cname records for {domain} after {maxRetries} attempts! ({ex.Message})");
                }
                else
                {
                    // Exponential backoff
                    await Task.Delay(100 * retryCount);
                }
            }
        }
    }

    // Cache checked domain registrations since I'm sure most runs of this tool will have lots of subdomains per root
    private readonly ConcurrentDictionary<string, bool> _domainCache = new();
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _domainLocks = new();
    private async Task<bool> CheckDomainRegistration(string domain)
    {
        try
        {
            // Normalize and extract the registrable part of the domain
            var normalizedDomain = domain.Trim().ToLower().Trim('.');

            if (!_domainParser.IsValidDomain(normalizedDomain))
            {
                return true;
            }

            // Extract the registrable part of the domain
            var domainData = _domainParser.Parse(normalizedDomain);
            var registrableDomain = domainData.RegistrableDomain;

            var domainLock = _domainLocks.GetOrAdd(registrableDomain, _ => new SemaphoreSlim(1, 1));
            await domainLock.WaitAsync();

            bool isRegistered = true;
            try
            {
                if (_domainCache.TryGetValue(registrableDomain, out isRegistered))
                {
                    return isRegistered;
                }

                var response = await new Whois.WhoisLookup().LookupAsync(registrableDomain);
                var whoisResponse = response.Content;

                if (string.IsNullOrWhiteSpace(whoisResponse))
                {
                    isRegistered = true;
                }
                else
                {
                    isRegistered = IsDomainRegistered(whoisResponse);
                }
                _domainCache[registrableDomain] = isRegistered;
            }
            finally
            {
                domainLock.Release();
            }

            return isRegistered;
        }
        catch (Exception)
        {
            return true;
        }
    }

    private bool IsDomainRegistered(string whoisResponse)
    {
        // Expanded checks for indicators of a registered domain
        var registrationIndicators = new List<string>
        {
            "Registrant:",
            "Registrant Contact:",
            "Registry Registrant ID",
            "Admin Contact:",
            "Tech Contact:",
            "Name Server:",
            "Creation Date:",
            "Updated Date:",
            "Registry Domain ID",
            "Domain Status",
            "Registrar:",
            "Expiration Date:",
            "Whois Server"
        };

        foreach (var indicator in registrationIndicators)
        {
            if (whoisResponse.Contains(indicator, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        // Additional logic to handle common negative responses
        var unregisteredIndicators = new List<string>
        {
            "No match for",
            "No entries found",
            "NOT FOUND",
            "No data found"
        };

        foreach (var indicator in unregisteredIndicators)
        {
            if (whoisResponse.Contains(indicator, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        // If none of the indicators are found, the domain's registration status is ambiguous
        return true;
    }

    public async Task<HttpResponseMessage?> HttpGet(string domain, bool redirect = true)
    {
        var client = redirect ? _httpClient : _httpClientNoRedirect;
        try
        {
            return await client.GetAsync($"https://{domain}");
        }
        catch (HttpRequestException ex) when (ex.Message.Contains("No such host is known.")) 
        {
            // We could just skip HTTP requests when we detect NXDOMAIN responses but there's edge cases.
            // For example, there could be an A record that points to an IP on a vulnerable domain
            return null;
        }
        catch
        {
            // Try again with HTTP just in case
            try
            {
                return await client.GetAsync($"http://{domain}");
            }
            catch
            {
                // Sometimes the site is just having a bad day and that's okay
                return new HttpResponseMessage();
            }
        }
    }
}
