using Subdominator.Models;

namespace Subdominator.Validators;

public class VercelValidator : IValidator
{
    public async Task<bool?> Execute(IEnumerable<string> cnames)
    {
        // Vercel'e özgü doğrulama mantığı
        foreach (var cname in cnames)
        {
            if (cname.Contains("vercel.com", StringComparison.OrdinalIgnoreCase) || 
                cname.Contains("vercel-dns.com", StringComparison.OrdinalIgnoreCase))
            {
                // Burada ideal olarak Vercel API ile bu alan adının mevcut olup olmadığını kontrol etmeliyiz
                // Ancak şimdilik basit bir HTTP isteği ile kontrol edebiliriz
                try
                {
                    using var client = new HttpClient();
                    var response = await client.GetAsync($"https://{cname}");
                    
                    // 404 durum kodu veya belirli bir hata metni aranabilir
                    if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        // Alan adı mevcut değil, ele geçirilebilir
                        return true;
                    }
                    else
                    {
                        // Alan adı hala aktif, ele geçirilemez
                        return false;
                    }
                }
                catch
                {
                    // Bağlantı hatası - muhtemelen ele geçirilebilir
                    return true;
                }
            }
        }
        
        // Bu validatör bu alan adı için geçerli değil
        return null;
    }
}
