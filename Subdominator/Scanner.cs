using System.IO.Compression;
using System.Text.RegularExpressions;

namespace Subdominator;

public class Scanner
{
    public async Task<List<string>> FindVulnerableSubdomains()
    {
        var cnameRecords = new List<string>();
        var cnameDb = new HashSet<string>();

        // Download the latest file
        await RunWithSpinnerAsync("Downloading latest file (This may take a while).", async () =>
        {
            //TODO: Make this pull the file from disk (or the internet if possible)
            var fileContent = await DownloadFileAsync($"https://opendata.rapid7.com/file.zip");
            cnameRecords.AddRange(await ParseCnameRecordsAsync(fileContent));
        });

        // Process CNAME records
        cnameDb.UnionWith(cnameRecords.Select(record => record.Split(' ')[0]).Distinct());

        return cnameDb.ToList();
    }

    private async Task RunWithSpinnerAsync(string message, Func<Task> action)
    {
        var spinner = new[] { "|", "/", "-", "\\" };
        bool isCompleted = false;

        var spinnerTask = Task.Run(() =>
        {
            int spinnerIndex = 0;
            while (!isCompleted)
            {
                Console.Write($"\r[{spinner[spinnerIndex++ % spinner.Length]}] {message}");
                Task.Delay(150).Wait();
            }
        });

        await action();
        isCompleted = true;
        await spinnerTask;
    }

    private async Task<string> GetLatestFileNameAsync()
    {
        using var client = new HttpClient();
        string html = await client.GetStringAsync("https://opendata.rapid7.com/sonar.fdns_v2/");
        var match = Regex.Matches(html, "<td><a.*?href=\"(.*?)\".*?>").FirstOrDefault();
        return match?.Groups[1].Value.Split('/').Last();
    }

    private async Task<Stream> DownloadFileAsync(string url)
    {
        using var client = new HttpClient();
        var response = await client.GetAsync(url);
        return await response.Content.ReadAsStreamAsync();
    }

    private async Task<List<string>> ParseCnameRecordsAsync(Stream dataStream)
    {
        var cnameRecords = new List<string>();
        var domains = new string[] 
        {
            ".cloudfront.net",
            ".s3-website",
            ".s3.amazonaws.com",
            "w.amazonaws.com",
            "1.amazonaws.com",
            "2.amazonaws.com",
            "s3-external",
            "s3-accelerate.amazonaws.com",
            ".herokuapp.com",
            ".herokudns.com",
            ".wordpress.com",
            ".pantheonsite.io",
            "domains.tumblr.com",
            ".zendesk.com",
            ".github.io",
            ".global.fastly.net",
            ".helpjuice.com",
            ".helpscoutdocs.com",
            ".ghost.io",
            "cargocollective.com",
            "redirect.feedpress.me",
            ".myshopify.com",
            ".statuspage.io",
            ".uservoice.com",
            ".surge.sh",
            ".bitbucket.io",
            "custom.intercom.help",
            "proxy.webflow.com",
            "landing.subscribepage.com",
            "endpoint.mykajabi.com",
            ".teamwork.com",
            ".thinkific.com",
            "clientaccess.tave.com",
            "wishpond.com",
            ".aftership.com",
            "ideas.aha.io",
            "domains.tictail.com",
            "cname.mendix.net",
            ".bcvp0rtal.com",
            ".brightcovegallery.com",
            ".gallery.video",
            ".bigcartel.com",
            ".activehosted.com",
            ".createsend.com",
            ".acquia-test.co",
            ".proposify.biz",
            "simplebooklet.com",
            ".gr8.com",
            ".vendecommerce.com",
            ".azurewebsites.net",
            ".cloudapp.net",
            ".trafficmanager.net",
            ".blob.core.windows.net"
        };
        var domainPattern = string.Join("|", domains.Select(Regex.Escape));

        using var decompressionStream = new GZipStream(dataStream, CompressionMode.Decompress);
        using var reader = new StreamReader(decompressionStream);
        string line;
        while ((line = await reader.ReadLineAsync()) != null)
        {
            if (Regex.IsMatch(line, "\"type\":\"cname\"") && Regex.IsMatch(line, domainPattern))
            {
                var parts = line.Split(new[] { "type\":\"cname", "\"" }, StringSplitOptions.RemoveEmptyEntries);
                cnameRecords.Add($"{parts[0]} {parts[1]}");
            }
        }

        return cnameRecords;
    }
}
