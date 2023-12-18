using Subdominator.Validators;

namespace Subdominator.Tests;

[TestClass]
public class ValidatorTests
{
    [TestInitialize]
    public async Task Setup()
    {
        
    }

    [TestMethod]
    public async Task ShouldMatchAzureDomains()
    {
        // Invalid App Service
        var validator = new MicrosoftAzureValidator();
        var result = await validator.Execute(new List<string> { "aaaaaaaaaaathiswillneverberealaaaaaaaaaaa.azurewebsites.net" });
        Assert.IsTrue(result);

        // Valid App Service
        result = await validator.Execute(new List<string> { "site.azurewebsites.net" });
        Assert.IsFalse(result);

        // Invalid Traffic Manager
        result = await validator.Execute(new List<string> { "aaaaaaaaaaathiswillneverberealaaaaaaaaaaa.trafficmanager.net" });
        Assert.IsTrue(result);

        // Valid Traffic Manager
        result = await validator.Execute(new List<string> { "site.trafficmanager.net" });
        Assert.IsFalse(result);
    }

    [TestMethod]
    public async Task ShouldMatchAwsDomains()
    {
        // Invalid beanstalk
        var validator = new AWSElasticBeanstalkValidator();
        var result = await validator.Execute(new List<string> { "aaaaaaaaaaathiswillneverberealaaaaaaaaaaa.us-east-1.elasticbeanstalk.com" });
        Assert.IsTrue(result);

        // Valid beanstalk
        result = await validator.Execute(new List<string> { "site.us-east-1.elasticbeanstalk.com" });
        Assert.IsFalse(result);

        // Valid beanstalk with environment ID
        result = await validator.Execute(new List<string> { "site.asconuiac.us-east-1.elasticbeanstalk.com" });
        Assert.IsFalse(result);
    }
}
