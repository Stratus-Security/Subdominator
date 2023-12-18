using Amazon;
using Amazon.ElasticBeanstalk;

namespace Subdominator.Validators;

public class AWSElasticBeanstalkValidator : IValidator
{
    public async Task<bool?> Execute(IEnumerable<string> cnames)
    {
        var isChecked = false;

        foreach (var rawCname in cnames)
        {
            var cname = rawCname.Trim('.'); // DNS likes to returns dots at the end

            // There are 3 formats for a beanstalk cname:
            //  - <app-name>.<region>.elasticbeanstalk.com
            //  - <app-name>.<environment-id>.<region>.elasticbeanstalk.com
            //  - <app-name>.elasticbeanstalk.com (Legacy, no longer registerable)
            var cnameParts = cname.Split('.');
            // <app-name>.elasticbeanstalk.com is the legacy format and no longer able to be registered
            if (!cname.EndsWith("elasticbeanstalk.com") || cnameParts.Length <= 3)
            {
                isChecked = true;
                continue;
            }

            // Extract the app name (always the first bit)
            var appname = cnameParts[0];

            // Extract the region, it's always the last part before elasticbeanstalk.com in the known formats
            string region = cnameParts[cnameParts.Length - 3];
            
            // Now we can check
            var client = new AmazonElasticBeanstalkClient(RegionEndpoint.GetBySystemName(region));
            var result = await client.CheckDNSAvailabilityAsync(
                new Amazon.ElasticBeanstalk.Model.CheckDNSAvailabilityRequest
                {
                    CNAMEPrefix = appname,
                }
            );
            if (result.Available)
            {
                return true;
            }
            else
            {
                isChecked = true;
            }
        }

        // If we have checked records and none matched, it's a false positive, other it's unknown
        return isChecked ? false : null;
    }
}
