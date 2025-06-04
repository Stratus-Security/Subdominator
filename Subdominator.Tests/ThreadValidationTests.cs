using Subdominator;

namespace Subdominator.Tests;

[TestClass]
public class ThreadValidationTests
{
    [TestMethod]
    public void InvalidThreadValuesDefaultTo50()
    {
        Assert.AreEqual(50, Program.ValidateThreadCount(0));
        Assert.AreEqual(50, Program.ValidateThreadCount(-5));
        Assert.AreEqual(10, Program.ValidateThreadCount(10));
    }
}
