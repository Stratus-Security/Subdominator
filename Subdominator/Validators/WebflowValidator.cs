using Subdominator.Models;

namespace Subdominator.Validators;

public class WebflowValidator : IValidator
{
    public async Task<bool?> Execute(IEnumerable<string> cnames)
    {
        // Webflow-specific validation logic
        foreach (var cname in cnames)
        {
            if (cname.Contains("webflow.com", StringComparison.OrdinalIgnoreCase))
            {
                // Algorithm to check Webflow domains
                try
                {
                    using var client = new HttpClient();
                    var response = await client.GetAsync($"https://{cname}");
                    
                    // Webflow's 404 page usually has specific content
                    if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        if (content.Contains("The page you are looking for doesn't exist") ||
                            content.Contains("website has been archived or deleted"))
                        {
                            return true; // Domain is vulnerable to takeover
                        }
                    }
                    
                    return false; // Domain is active, not vulnerable
                }
                catch
                {
                    // Connection error - potentially vulnerable
                    return true;
                }
            }
        }
        
        // This validator is not applicable for this domain
        return null;
    }
}
