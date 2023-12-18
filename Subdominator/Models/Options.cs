namespace Subdominator.Models;

public class Options
{
    public string Domain { get; set; }
    public string DomainsFile { get; set; }
    public string OutputFile { get; set; }
    public int Threads { get; set; }
    public bool Verbose { get; set; }
    public bool ExcludeUnlikely { get; set; }
    public bool Validate { get; set; }
}
