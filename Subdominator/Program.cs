namespace Subdominator;

internal class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("Enter a domain to check for subdomain hijack vulnerability:");
        string domain = Console.ReadLine();

        var hijackChecker = new SubdomainHijack();
        var isVulnerable = await hijackChecker.IsDomainVulnerable(domain);
        Console.WriteLine($"{domain} is{(isVulnerable ? "" : " not")} vulnerable.");
    }
}