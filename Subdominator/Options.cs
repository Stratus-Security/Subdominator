using CommandLine;

namespace Subdominator;

public class Options
{
    [Option('d', "domain", Required = false, HelpText = "A single domain to check")]
    public string Domain { get; set; }

    [Option('l', "list", Required = false, HelpText = "A line delimited list of domains to check")]
    public string DomainsFile { get; set; }

    [Option('o', "output", Required = false, HelpText = "Output subdomains to a file (line delimited)")]
    public string OutputFile { get; set; }
}
