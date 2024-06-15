using System.CommandLine.Binding;
using System.CommandLine;
using Subdominator.Models;
using System.Reflection;

namespace Subdominator
{
    public class OptionsBinder : BinderBase<Options>
    {
        private readonly List<Option> _options;

        public OptionsBinder(List<Option> options)
        {
            _options = options;
        }

        protected override Options GetBoundValue(BindingContext bindingContext)
        {
            var options = new Options();
            var optionType = typeof(Options);
            var properties = optionType.GetProperties(BindingFlags.Public | BindingFlags.Instance);

            foreach (var option in _options)
            {
                var property = properties.FirstOrDefault(p => string.Equals(p.Name, option.Name, StringComparison.OrdinalIgnoreCase));
                if (property != null)
                {
                    var convertedValue = Convert.ChangeType(bindingContext.ParseResult.GetValueForOption(option), property.PropertyType);
                    property.SetValue(options, convertedValue);
                }
            }

            return options;
        }
    }
}
