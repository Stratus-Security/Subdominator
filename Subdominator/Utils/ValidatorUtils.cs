using Subdominator.Validators;

namespace Subdominator.Utils;

public static class ValidatorUtils
{
    private static IValidator _azureValidator = new MicrosoftAzureValidator();

    // This could use reflection but it will break AoT compilation.
    // Instead, it needs to have any new validators manually added.
    // The validator key is same as the fingerprint name/service, minus any '/' or ' ' chars
    public static IValidator? GetValidatorInstance(string key)
    {
        return key switch
        {
            "MicrosoftAzure" => _azureValidator, // Use a global instance so it only asks for creds once
            "AWSElasticBeanstalk" => new AWSElasticBeanstalkValidator(),
            "Vercel" => new VercelValidator(),
            "Webflow" => new WebflowValidator(),
            _ => null,
        };
    }
}
