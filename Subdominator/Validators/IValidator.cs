namespace Subdominator.Validators;

public interface IValidator
{
    Task<bool?> Execute(IEnumerable<string> cnames);
}
