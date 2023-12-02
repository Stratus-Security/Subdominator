using System.Text.Json.Serialization;

namespace Subdominator;

[JsonSerializable(typeof(List<Fingerprint>))]
public partial class JsonContext : JsonSerializerContext
{
}