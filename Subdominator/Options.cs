using CommandLine;

namespace Subdominator;

public class Options
{
    [Option('d', "domain", Required = false, HelpText = "A single domain to check")]
    public string Domain { get; set; }

    [Option('l', "list", Required = false, HelpText = "A list of domains to check (line delimited)")]
    public string DomainsFile { get; set; }

    [Option('o', "output", Required = false, HelpText = "Output subdomains to a file")]
    public string OutputFile { get; set; }

    [Option('t', "threads", Required = false, HelpText = "Number of domains to check at once", Default = 50)]
    public int Threads { get; set; }

    [Option('v', "verbose", Required = false, HelpText = "Print extra information")]
    public bool Verbose { get; set; }
}
