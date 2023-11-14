using System.Net;

namespace Subdominator.Tests;

[TestClass]
public class FingerprintTests
{
    private SubdomainHijack _subdomainHijack;
    private IEnumerable<Fingerprint> _fingerprints;

    [TestInitialize]
    public async Task Setup()
    {
        _subdomainHijack = new SubdomainHijack();
        _fingerprints = await _subdomainHijack.GetFingerprintsAsync();
    }

    [TestMethod]
    public async Task TestFingerprints()
    {
        foreach (var fingerprint in _fingerprints)
        {
            foreach (var cname in fingerprint.Cnames)
            {
                IEnumerable<string>? subdomainCnames;
                string randomSubdomain;

                // Since we're directly grabbing expected cname values, there's sometimes IPs.
                // These will be incorrectly flagged with NXDOMAIN and don't need a subdomain
                if (IPAddress.TryParse(cname, out _))
                {
                    subdomainCnames = new List<string>();
                    randomSubdomain = cname;
                }
                else
                {
                    subdomainCnames = await _subdomainHijack.GetCnamesForSubdomain(cname);
                    randomSubdomain = GenerateRandomSubdomain(cname);
                }

                HttpResponseMessage? response = null;
                string responseBody = "";
                if (subdomainCnames != null)
                {
                    response = await _subdomainHijack.HttpGet(randomSubdomain, !(fingerprint.HttpStatus >= 300 && fingerprint.HttpStatus < 400));
                    if(response != null)
                    {
                        responseBody = await response.Content.ReadAsStringAsync();
                    }
                }

                var isVulnerable = _subdomainHijack.IsFingerprintVulnerable(fingerprint, subdomainCnames, responseBody, response?.StatusCode);
                Console.WriteLine($"Fingerprint: {fingerprint.Service} -- Vulnerable: {isVulnerable}");
            }
        }
    }

    private string GenerateRandomSubdomain(string baseCname)
    {
        var random = new Random();
        const string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        var subdomain = new string(Enumerable.Repeat(chars, 12)
          .Select(s => s[random.Next(s.Length)]).ToArray());

        return $"{subdomain}.{baseCname}";
    }
}