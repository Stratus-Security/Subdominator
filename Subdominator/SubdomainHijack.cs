using DnsClient;
using System.Net;
using System.Text.Json;

namespace Subdominator;

public class SubdomainHijack
{
    private readonly HttpClient _httpClient;
    private readonly HttpClient _httpClientNoRedirect;
    private readonly LookupClient _dnsClient;
    private List<Fingerprint> _fingerprints = new List<Fingerprint>();

    // Some of the fingerprints are incorrectly labelled - these are all at least edge cases
    private IEnumerable<string> _overrides = new List<string>()
    {
        "Acquia",
        "Fastly",
        "Unbounce",
        "Zendesk"
    };

    public SubdomainHijack()
    {
        var handler = new HttpClientHandler
        {
            // Invalid SSL should be allowed
            ServerCertificateCustomValidationCallback = (message, certificate2, chain, errors) => true
        };
        _httpClient = new HttpClient(handler);

        // We want to ignore redirects when expecting something like a 301 and follow otherwise to get the best results
        handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, certificate2, chain, errors) => true,
            AllowAutoRedirect = false
        };
        _httpClientNoRedirect = new HttpClient(handler);

        _dnsClient = new LookupClient();
    }

    //TODO: Add additional (custom) fingerprints to make up for gaps
    public async Task<IEnumerable<Fingerprint>> GetFingerprintsAsync(bool update = false)
    {
        // Don't reload if they're already cached in memory
        if (!_fingerprints.Any())
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
                    var customFingerprintsUrl = "https://raw.githubusercontent.com/Stratus-Security/Subdominator/master/custom_fingerprints.json";
                    customFingerprintsData = await _httpClient.GetStringAsync(customFingerprintsUrl);

                    await File.WriteAllTextAsync(customFilePath, customFingerprintsData);
                }

                // Deserialize the JSON data directly into a list of Fingerprint objects
                var fingerprints = JsonSerializer.Deserialize<List<Fingerprint>>(fingerprintsData) ?? new List<Fingerprint>();
                var customFingerprints = JsonSerializer.Deserialize<List<Fingerprint>>(customFingerprintsData) ?? new List<Fingerprint>();

                // Find and store appropriate fingerprints
                foreach (var fingerprint in fingerprints)
                {
                    // The override list contains edge cases that were incorrectly marked
                    if (_overrides.Contains(fingerprint.Service))
                    {
                        fingerprint.Status = "Edge case";
                    }

                    // Now ignore any non-vulnerable fingerprints
                    if (fingerprint.Status.ToLower() != "not vulnerable")
                    {
                        fingerprint.CompileRegex();
                        _fingerprints.Add(fingerprint);
                    }
                }

                // Now iterate custom fingerprints. The custom list is used for completeness, so it should not override the original
                foreach(var fingerprint in customFingerprints)
                {
                    if (fingerprint.Status.ToLower() != "not vulnerable" && !_fingerprints.Any(f => f.Service.ToLower() == fingerprint.Service.ToLower()))
                    {
                        fingerprint.CompileRegex();
                        _fingerprints.Add(fingerprint);
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

    public async Task<bool> IsDomainVulnerable(string domain, bool update = false)
    {
        var fingerprints = await GetFingerprintsAsync(update);

        // DNS Lookup
        var subdomainCnames = await GetCnamesForSubdomain(domain);

        // Only send the request once per domain - we will always want to check the HTTP response
        HttpResponseMessage? response = null;
        string? responseBody = null;

        foreach (var fingerprint in _fingerprints)
        {
            if (fingerprint.Cnames != null && (subdomainCnames == null || subdomainCnames.Any()) && fingerprint.Cnames.Any(cname => subdomainCnames.Contains(cname)))
            {
                // Make sure we only send a single HTTP request if multiple fingerprints match
                if (response == null || responseBody == null)
                {
                    response = await HttpGet(domain, fingerprint.HttpStatus >= 300 && fingerprint.HttpStatus < 400);
                    if (response == null)
                    {
                        responseBody = "";
                    }
                    else
                    {
                        responseBody = await response.Content.ReadAsStringAsync();
                    }
                }

                if(IsFingerprintVulnerable(fingerprint, subdomainCnames, responseBody, response?.StatusCode))
                {
                    return true;
                }
            }
        }

        return false;
    }

    public bool IsFingerprintVulnerable(Fingerprint fingerprint, IEnumerable<string>? cnames, string responseBody, HttpStatusCode? statusCode)
    {
        // Check if NXDOMAIN indicates takeover (Note: CNAME list only returns null for NXDOMAIN)
        if (fingerprint.Nxdomain && cnames == null)
        {
            //TODO: Add domain registration checker to validate if it is available
            return fingerprint.Vulnerable;
        }

        // Check if HTTP status matches the fingerprint
        if (fingerprint.HttpStatus.HasValue && statusCode.HasValue && (int)statusCode == fingerprint.HttpStatus.Value)
        {
            return fingerprint.Vulnerable;
        }

        // Check response content if available
        if (fingerprint.FingerprintTexts.Any() && !string.IsNullOrWhiteSpace(responseBody))
        {
            foreach(var regex in fingerprint.FingerprintRegexes)
            {
                if (regex.IsMatch(responseBody))
                {
                    return fingerprint.Vulnerable;
                }
            }
        }

        return false;
    }

    public async Task<IEnumerable<string>?> GetCnamesForSubdomain(string domain)
    {
        try
        {
            var result = await _dnsClient.QueryAsync(domain, QueryType.CNAME);
            // Check for NXDOMAIN (non-existent domain)
            if (result.Header.ResponseCode == DnsHeaderResponseCode.NotExistentDomain)
            {
                return null; // NXDOMAIN condition
            }
            else if(result.HasError)
            {

            }
            return result.Answers.CnameRecords().Select(c => c.CanonicalName.Value);
        }
        catch (Exception ex)
        {
            // Other exceptions
            throw new Exception($"Exception thrown trying to get cname records for {domain}! ({ex.Message})");
        }
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
            // We could just skip HTTP requests when we detect NXDOMAIN responses but there's edge cases
            // For example, there could be an A record that points to an IP on a vulnerable domain
            return null;
        }
        catch
        {
            // Try again with HTTP just in case
            return await client.GetAsync($"http://{domain}");
        }
    }
}
