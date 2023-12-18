using Azure.Identity;
using Azure.ResourceManager.TrafficManager;
using Azure.ResourceManager.TrafficManager.Models;
using Azure.ResourceManager.AppService;
using Azure.ResourceManager.AppService.Models;
using Azure.ResourceManager;
using Azure.ResourceManager.Resources;
using Azure.Core;

namespace Subdominator.Validators;

public class MicrosoftAzureValidator : IValidator
{
    private readonly SubscriptionResource _subscription;

    public MicrosoftAzureValidator()
    {
        TokenCredential credential = new DefaultAzureCredential();
        var armClient = new ArmClient(credential);

        try
        {
            _subscription = armClient.GetDefaultSubscription();
        }
        catch
        {
            // Fall back to manual login if no creds are found
            credential = new InteractiveBrowserCredential();
            armClient = new ArmClient(credential);
            _subscription = armClient.GetDefaultSubscription();
        }
    }

    public async Task<bool?> Execute(IEnumerable<string> cnames)
    {
        var isChecked = false;

        foreach (var rawCname in cnames)
        {
            var cname = rawCname.Trim('.'); // DNS likes to returns dots at the end
            if (cname.ToLower().Contains("cloudapp.net"))
            {
                // Check Azure Virtual Machines and Cloud Services (API Not Available in Azure yet)
                //return await CheckCloudAppNet(cname);
            }
            else if (cname.ToLower().Contains("azurewebsites.net"))
            {
                // Check Azure App Services
                var isAvailable = await CheckAzureWebsitesNet(cname);

                // Only return if available so we can check nested records
                if (isAvailable)
                {
                    return true;
                }
                else
                {
                    isChecked = true;
                }
            }
            else if (cname.ToLower().Contains("cloudapp.azure.com"))
            {
                // Check Azure VM Scale Sets (API Not Available in Azure yet)
                // await CheckCloudAppAzureCom(cname);
            }
            else if (cname.ToLower().Contains("trafficmanager.net"))
            {
                // Check Azure Traffic Manager
                var isAvailable = await CheckTrafficManagerNet(cname);
                if (isAvailable)
                {
                    return true;
                }
                else
                {
                    isChecked = true;
                }
            }
            else if (cname.ToLower().Contains("azureedge.net"))
            {
                // Check Azure CDN (Classic) Endpoint
                // await CheckAzureCdn(cname);
            }
        }

        // If we have checked records and none matched, it's a false positive, other it's unknown
        return isChecked ? false : null;
    }

    private async Task<bool> CheckAzureCdn(string cname)
    {
        throw new NotImplementedException();
    }

    private async Task<bool> CheckCloudAppNet(string cname)
    {
        throw new NotImplementedException();
    }

    private async Task<bool> CheckAzureWebsitesNet(string cname)
    {
        // We might end up with things like *.privatelink.azurewebsites.net or *.scm
        // They are linked to *.azurewebsites.net so we don't need to check the whole thing
        var resourceName = cname.Split('.')[0];
        var resourceType = CheckNameResourceType.MicrosoftWebSites;
        //TODO: Do we need to manage app service slots?
        var result = await _subscription.CheckAppServiceNameAvailabilityAsync(new ResourceNameAvailabilityContent(resourceName, resourceType));

        return result.Value.IsNameAvailable ?? false;
    }

    private async Task<bool> CheckCloudAppAzureCom(string cname)
    {
        throw new NotImplementedException();
    }

    private async Task<bool> CheckTrafficManagerNet(string cname)
    {
        var content = new TrafficManagerRelativeDnsNameAvailabilityContent()
        {
            Name = cname.Split('.')[0],
            ResourceType = new ResourceType("microsoft.network/trafficmanagerprofiles"),
        };
        var result = await _subscription.CheckTrafficManagerNameAvailabilityV2Async(content);

        return result.Value.IsNameAvailable ?? false;
    }
}
