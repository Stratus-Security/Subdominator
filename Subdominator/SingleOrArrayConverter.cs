using System.Text.Json.Serialization;
using System.Text.Json;

namespace Subdominator;

public class SingleOrArrayConverter<T> : JsonConverter<List<T>>
{
    public override List<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        List<T> list = new List<T>();
        if (reader.TokenType == JsonTokenType.StartArray)
        {
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndArray) return list;
                list.Add(JsonSerializer.Deserialize<T>(ref reader, options));
            }
        }
        else
        {
            var value = JsonSerializer.Deserialize<T>(ref reader, options);
            list.Add(value);
        }
        return list;
    }

    public override void Write(Utf8JsonWriter writer, List<T> value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(writer, value, options);
    }
}
