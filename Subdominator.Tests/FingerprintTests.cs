using Subdominator.Models;
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
    public void ShouldNotHaveDuplicateServices()
    {
        Assert.IsTrue(
            _fingerprints.Count() == _fingerprints.DistinctBy(f => f.Service.ToLower().Replace(" ", "")).Count()
        );
    }

    [TestMethod]
    public async Task TestFingerprints()
    {
        foreach (var fingerprint in _fingerprints)
        {
            foreach (var cname in fingerprint.Cnames)
            {
                CnameResolutionResult subdomainCnames;
                string randomSubdomain;

                // Since we're directly grabbing expected cname values, there's sometimes IPs.
                // These will be incorrectly flagged with NXDOMAIN and don't need a subdomain
                if (IPAddress.TryParse(cname, out _))
                {
                    subdomainCnames = new();
                    randomSubdomain = cname;
                }
                else
                {
                    subdomainCnames = await _subdomainHijack.GetDnsForSubdomain(cname);
                    randomSubdomain = GenerateRandomSubdomain(cname);
                }

                var isVulnerable = await _subdomainHijack.IsFingerprintVulnerable(fingerprint, subdomainCnames, randomSubdomain);
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