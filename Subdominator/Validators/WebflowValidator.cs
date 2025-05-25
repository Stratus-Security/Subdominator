using Subdominator.Models;

namespace Subdominator.Validators;

public class WebflowValidator : IValidator
{
    public async Task<bool?> Execute(IEnumerable<string> cnames)
    {
        // Webflow'a özgü doğrulama mantığı
        foreach (var cname in cnames)
        {
            if (cname.Contains("webflow.com", StringComparison.OrdinalIgnoreCase))
            {
                // Webflow alan adlarını kontrol eden algoritma
                try
                {
                    using var client = new HttpClient();
                    var response = await client.GetAsync($"https://{cname}");
                    
                    // Webflow'un 404 sayfasında genellikle belirli içerikler vardır
                    if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        if (content.Contains("The page you are looking for doesn't exist") ||
                            content.Contains("website has been archived or deleted"))
                        {
                            return true; // Alan adı ele geçirilebilir
                        }
                    }
                    
                    return false; // Alan adı aktif, ele geçirilemez
                }
                catch
                {
                    // Bağlantı hatası - potansiyel olarak ele geçirilebilir
                    return true;
                }
            }
        }
        
        // Bu validatör bu alan adı için geçerli değil
        return null;
    }
}
