using Subdominator.Validators;

namespace Subdominator.Utils;

public static class ValidatorUtils
{
    // This could use reflection but it will break AoT compilation.
    // Instead, it needs to have any new validators manually added.
    // The validator key is same as the fingerprint name/service, minus any '/' or ' ' chars
    public static IValidator? GetValidatorInstance(string key)
    {
        return key switch
        {
            "MicrosoftAzure" => new MicrosoftAzureValidator(),
            "AWSElasticBeanstalk" => new AWSElasticBeanstalkValidator(),
            _ => null,
        };
    }
}
