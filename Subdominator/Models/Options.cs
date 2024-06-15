namespace Subdominator.Models;

public class Options
{
    public string Domain { get; set; }
    public string DomainsFile { get; set; }
    public string OutputFile { get; set; }
    public string CsvHeading { get; set; }
    public int Threads { get; set; } = 50;
    public bool Verbose { get; set; }
    public bool ExcludeUnlikely { get; set; }
    public bool Validate { get; set; }
    public bool Quiet { get; set; }
}
