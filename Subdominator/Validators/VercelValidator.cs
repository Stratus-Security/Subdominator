using Subdominator.Models;

namespace Subdominator.Validators;

public class VercelValidator : IValidator
{
    public async Task<bool?> Execute(IEnumerable<string> cnames)
    {
        // Vercel-specific validation logic
        foreach (var cname in cnames)
        {
            if (cname.Contains("vercel.com", StringComparison.OrdinalIgnoreCase) || 
                cname.Contains("vercel-dns.com", StringComparison.OrdinalIgnoreCase))
            {
                // Ideally, we should check if this domain exists using Vercel API
                // But for now, we can check with a simple HTTP request
                try
                {
                    using var client = new HttpClient();
                    var response = await client.GetAsync($"https://{cname}");
                    
                    // Check for 404 status code or specific error text
                    if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        // Domain doesn't exist, vulnerable to takeover
                        return true;
                    }
                    else
                    {
                        // Domain is still active, not vulnerable
                        return false;
                    }
                }
                catch
                {
                    // Connection error - likely vulnerable
                    return true;
                }
            }
        }
        
        // This validator is not applicable for this domain
        return null;
    }
}
