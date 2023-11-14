using System.Text.Json;

namespace Subdominator.Tests;

[TestClass]
public class CoverageTests
{
    private HttpClient _http;

    [TestInitialize]
    public async Task Setup()
    {
        _http = new HttpClient();
    }

    [TestMethod]
    public async Task TestCoverage()
    {
        var myFingerprints = await new SubdomainHijack().GetFingerprintsAsync();
        var canITakeOverFingerprints = GetCanITakeOverXyzFingerprints();
        var subdoverFingerprints = GetSubdoverFingerprints();
        var subjackFingerprints = GetSubjackFingerprints();
        var dnsReaperFingerprints = GetDnsReaperFingerprints();


    }

    private async Task<List<Fingerprint>> GetCanITakeOverXyzFingerprints()
    {
        var canitakeoverxyzFingerprintJson = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json";
        var fingerprintsData = await _http.GetStringAsync(canitakeoverxyzFingerprintJson);
        return JsonSerializer.Deserialize<List<Fingerprint>>(fingerprintsData) ?? new List<Fingerprint>();
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

        int endIndex = pythonFileContent.IndexOf(endIndicator, startIndex);
        if (endIndex == -1)
        {
            throw new Exception("Unable to parse Subdover fingerprints, end not found"); // End indicator not found, throw
        }
        endIndex += 1; // Adjust to include the closing bracket ']'

        // Now we need to parse the json into objects following our structure
        var subdoverJson = pythonFileContent[startIndex..endIndex];

        // Replace Python-style comments to make it JSON-compatible
        string jsonCompatibleString = subdoverJson.Replace("#", "//");

        // Grab their array of arrays as objects because I'm too lazy to add classes for each provider
        var rawFingerprints = JsonSerializer.Deserialize<List<List<object>>>(jsonCompatibleString);
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
                FingerprintTexts = new List<string> { rawFingerprint[3].ToString() }
            };

            fingerprints.Add(fingerprint);
        }

        return fingerprints;
    }

    private async Task<List<Fingerprint>> GetSubjackFingerprints()
    {
        var subjackFingerprintJson = "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json";

        return null;
    }

    private async Task<List<Fingerprint>> GetDnsReaperFingerprints()
    {
        var dnsReaperSignaturs = "https://api.github.com/repos/punk-security/dnsReaper/contents/signatures?ref=main";

        return null;
    }
}
