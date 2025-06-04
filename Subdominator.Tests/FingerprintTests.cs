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
        _fingerprints = await _subdomainHijack.GetFingerprintsAsync(false);
    }

    [TestMethod]
    public void ShouldNotHaveDuplicateServices()
    {
        Assert.IsTrue(
            _fingerprints.Count() == _fingerprints.DistinctBy(f => f.Service.ToLower().Replace(" ", "")).Count()
        );
    }

    /// <summary>
    /// This test is a good way to check everything works
    /// It will also detect some as vulnerable if the fingerprint matches without a valid parent pointing to it
    /// </summary>
    /// <returns></returns>
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

    [TestMethod]
    public async Task ShouldExcludeEdgeCaseFingerprints()
    {
        var hijack = new SubdomainHijack();
        var allFingerprints = await hijack.GetFingerprintsAsync(false);
        Assert.IsTrue(allFingerprints.Any(f => f.Status.ToLower() == "edge case"));

        hijack = new SubdomainHijack();
        var filteredFingerprints = await hijack.GetFingerprintsAsync(true);
        Assert.IsFalse(filteredFingerprints.Any(f => f.Status.ToLower() == "edge case"));
    }
}