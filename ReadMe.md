![GitHub Actions CI](https://github.com/Stratus-Security/Subdominator/workflows/CI/badge.svg)
![GitHub all releases](https://img.shields.io/github/downloads/Stratus-Security/Subdominator/total)

# Subdominator 🚀

## Welcome to the Subdominator Club!
Meet **Subdominator**, your new favourite CLI tool for detecting subdomain takeovers. It's designed to be fast, accurate, and dependable, offering [a significant improvement over other available tools](https://www.stratussecurity.com/post/the-ultimate-subdomain-takeover-tool).

🔍 Precision and speed are our goal. Subdominator delivers better results without the wait, see the benchmark and feature comparison below for details.

## Installing 🛠️
To quickly, get up and running, you can download the latest release for [windows](https://github.com/Stratus-Security/Subdominator/releases/latest/download/Subdominator.exe) or [linux](https://github.com/Stratus-Security/Subdominator/releases/latest/download/Subdominator).
Alternatively, download it via CLI (remove .exe for linux version):
```base
wget https://github.com/Stratus-Security/Subdominator/releases/latest/download/Subdominator.exe
```

## Quick Start 🚦
To quickly check a list of domains, simply run: 
```
Subdominator.exe -l subdomains.txt -o takeovers.txt
```
Or to quickly check a single domain, run:
```
Subdominator.exe -d sub.example.com
```

## Options 🎛️
```
-d, --domain <domain>    A single domain to check
-l, --list <list>        A list of domains to check (line delimited)
-o, --output <output>    Output subdomains to a file
-t, --threads <threads>  Number of domains to check at once [default: 50]
-v, --verbose            Print extra information
-eu, --exclude-unlikely  Exclude unlikely (edge-case) fingerprints
-c, --csv <csv>          Column index or heading to parse for CSV file. Forces -l to read as CSV instead of line-delimited
--validate               Validate the takeovers are exploitable (where possible)
--version                Show version information
-?, -h, --help           Show help and usage information
```

## Output
There will be a periodic progress updates to the CLI, additionally output for vulnerable domains is indicated as shown below.

By default, only vulnerable domains will be printed or saved to the file along with the vulnerable DNS record(s).
The output format is as follows:
```
[Service Name] vulnerable.domain.com - RecordType: dns.record.com
```

For example, a vulnerable Azure CDN takeover will look like this:
```
[Microsoft Azure] example.stratussecurity.com - CNAME: stratus-cdn-stg.azureedge.net
``` 

If you use the verbose flag, it will print all domains checked. 
For example, this shows the same vulnerable domain and another non-vulnerable domain indicated by [-]:
```
[Microsoft Azure] example.stratussecurity.com - CNAME: stratus-cdn-stg.azureedge.net
[-] www.stratussecurity.com
```

Finally, if a domain is vulnerable and passes validation with the --validation flag, it will be prepended with a ✅.
These domains have been validated to be vulnerable with the services directly, not just the fingerprint. For example:
```
✅ [Microsoft Azure] example.stratussecurity.com - CNAME: stratus-cdn-stg.azureedge.net
```

## Demo
The tool running across 1000 passively gathered subdomains:
![Demo](https://raw.githubusercontent.com/Stratus-Security/Subdominator/master/Demo.gif)

## Benchmark 📊
A benchmark was run across ~100,000 subdomains to compare performance with other popular tools
| Tool         | Threads | Time Taken         |
|--------------|---------|--------------------|
| **Subdominator** | 50      | 19 minutes, 8 seconds |
| Subjack      | 50      | 2 hours, 30 minutes, 2 seconds |
| Subdover     | 50      | 2 hours, 33 minutes, 27 seconds |

## Key Features 🔥
- **Advanced DNS Matching**: Supports DNS matching for CNAME, A, and AAAA records.
- **Recursive DNS Queries**: Performs in-depth queries to enhance accuracy and reduce false positives.
- **Intelligent Domain Matching**: Uses a custom `public_suffix_list.dat` for more effective domain matching.
- **Domain Registration Detection**: Checks for unregistered domains, with a more reliable method compared to other tools.
- **High-Speed Performance**: Achieves faster results through intelligent DNS record matching.
- **Vetted Ruleset**: Includes a thoroughly reviewed and updated ruleset.
- **Comprehensive Detection**: Capable of identifying takeovers missed by other tools.
- **Validation**: Dynamic takeover validation modules to check beyond fingerprints.

## Feature Comparison 🥊
| Feature                          | Subdominator | Subjack | Subdover |
|----------------------------------|--------------|---------|----------|
| Advanced DNS Matching            | ✅          | ❌      | ❌       |
| Recursive DNS Queries            | ✅          | ❌      | ❌       |
| Intelligent Domain Matching      | ✅          | ❌      | ❌       |
| Domain Registration Detection    | ✅          | ✅      | ❌       |
| High-Speed Performance           | ✅          | ❌      | ❌       |
| Vetted and Updated Ruleset       | ✅          | ❌      | ❌       |
| Comprehensive Detection          | ✅          | ❌      | ❌       |
| Custom Fingerprint Support       | ✅          | ✅      | ❌       |
| Validation                       | ✅          | ❌      | ❌       |
| Fingerprints                     | 97           | 35      | 80       |

## Contributions
Got a suggestion, fingerprint, or want to chip in? We're all ears! Open a PR or issue – this will keep subdominator on top! 😄

## Fingerprints 
The fingerprints and services are dynamically pulled from the [CanITakeOverXYZ repo](https://github.com/EdOverflow/can-i-take-over-xyz) as a source of truth. To fill in the gaps and correct incorrect fingerprints, this tool also has its own [custom fingerprints list](https://github.com/Stratus-Security/Subdominator/blob/master/Subdominator/custom_fingerprints.json) which is used in conjunction.

Below is the current list of services supported, to ignore edge cases use the `-eu` flag.
| Service | Status |
|---------|--------|
| Acquia | Edge case |
| ActiveCampaign | Vulnerable |
| Aftership | Vulnerable |
| Agile CRM | Vulnerable |
| Aha | Vulnerable |
| Airee.ru | Vulnerable |
| Amazon Cognito | Vulnerable |
| Anima | Vulnerable |
| Announcekit | Vulnerable |
| Apigee | Vulnerable |
| Appery.io | Vulnerable |
| AWS/Elastic Beanstalk | Vulnerable |
| AWS/S3 | Vulnerable |
| Better Uptime | Vulnerable |
| BigCartel | Vulnerable |
| Bitbucket | Vulnerable |
| Branch.io | Vulnerable |
| Brandpad | Vulnerable |
| Brightcove | Vulnerable |
| Bubble.io | Vulnerable |
| Campaign Monitor | Vulnerable |
| Canny | Vulnerable |
| Cargo Collective | Vulnerable |
| ConvertKit | Vulnerable |
| DatoCMS.com | Vulnerable |
| Digital Ocean | Vulnerable |
| Discourse | Vulnerable |
| EasyRedir | Vulnerable |
| Fastly | Edge case |
| Flexbe | Edge Case |
| Flywheel | Vulnerable |
| Frontify | Edge case |
| Gemfury | Vulnerable |
| GetCloudApp | Vulnerable |
| Getresponse | Vulnerable |
| Ghost | Vulnerable |
| Gitbook | Vulnerable |
| Github | Edge case |
| HatenaBlog | Vulnerable |
| Help Juice | Vulnerable |
| Help Scout | Vulnerable |
| Helprace | Vulnerable |
| Heroku | Edge case |
| Instapage | Edge case |
| Intercom | Edge case |
| JazzHR | Edge Case |
| JetBrains | Vulnerable |
| Kajabi | Vulnerable |
| Landingi | Edge case |
| LaunchRock | Vulnerable |
| LeadPages.com | Vulnerable |
| Mashery | Edge case |
| Meteor Cloud (Galaxy) | Vulnerable |
| Microsoft Azure | Vulnerable |
| Netlify | Edge case |
| Ngrok | Vulnerable |
| Pagewiz | Vulnerable |
| Pantheon | Vulnerable |
| Pingdom | Vulnerable |
| Proposify | Vulnerable |
| Readme.io | Vulnerable |
| Readthedocs | Vulnerable |
| Refined | Vulnerable |
| Shopify | Edge case |
| Short.io | Vulnerable |
| SimpleBooklet | Vulnerable |
| SmartJobBoard | Vulnerable |
| Smartling | Edge case |
| Smugsmug | Vulnerable |
| Softr | Vulnerable |
| Sprintful | Vulnerable |
| Strikingly | Vulnerable |
| Surge.sh | Vulnerable |
| Surveygizmo | Vulnerable |
| SurveySparrow | Vulnerable |
| Tave | Vulnerable |
| Teamwork | Vulnerable |
| Thinkific | Vulnerable |
| Tictail | Vulnerable |
| Tilda | Edge case |
| Tribe | Vulnerable |
| Tumblr | Edge case |
| Uberflip | Vulnerable |
| Unbounce | Edge case |
| Uptimerobot | Vulnerable |
| UseResponse | Vulnerable |
| UserVoice | Edge case |
| Vend | Vulnerable |
| Vercel | Edge case |
| Webflow | Edge case |
| Wishpond | Vulnerable |
| Wix | Edge case |
| Wordpress | Vulnerable |
| Worksites | Vulnerable |
| Wufoo | Vulnerable |
| Zendesk | Edge case |
| Zoho Forms | Vulnerable |
| Zoho Forms India | Vulnerable |