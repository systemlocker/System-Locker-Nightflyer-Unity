// Strict JSON for the Nightflyer wire protocol. Unity's scripting profile
// cannot use System.Text.Json, so this in-house reader/writer provides the
// exact behaviors the protocol depends on:
//   - duplicate object members are rejected during parsing,
//   - nesting deeper than 32 levels is rejected,
//   - numbers keep their token text: callers decide whether an integer
//     interpretation exists (decimals, exponents, and overflowing values are
//     Number values that fail integer extraction, mirroring the server-side
//     reader semantics),
//   - strings are written with minimal escaping (control characters, quote,
//     and backslash only), which byte-matches the relaxed encoder used by the
//     other Nightflyer clients for protocol traffic.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SystemLocker.Nightflyer
{
    /// <summary>Raised when input is not strict JSON. <see cref="Duplicate"/> distinguishes duplicate members from every other malformation.</summary>
    internal sealed class NightflyerJsonException : Exception
    {
        public bool Duplicate { get; }

        public NightflyerJsonException(string message, bool duplicate = false) : base(message)
        {
            Duplicate = duplicate;
        }
    }

    internal enum NightflyerJsonValueKind
    {
        Object,
        Array,
        String,
        Number,
        True,
        False,
        Null,
    }

    internal sealed class NightflyerJsonProperty
    {
        public NightflyerJsonProperty(string name, NightflyerJsonNode value)
        {
            Name = name;
            Value = value;
        }

        public string Name { get; }
        public NightflyerJsonNode Value { get; }
    }

    internal sealed class NightflyerJsonNode
    {
        internal NightflyerJsonNode(NightflyerJsonValueKind kind, string? text, List<NightflyerJsonProperty>? properties, List<NightflyerJsonNode>? items)
        {
            Kind = kind;
            _text = text;
            _properties = properties;
            _items = items;
        }

        private readonly string? _text;
        private readonly List<NightflyerJsonProperty>? _properties;
        private readonly List<NightflyerJsonNode>? _items;

        public NightflyerJsonValueKind Kind { get; }

        internal static NightflyerJsonNode CreateObject(IEnumerable<NightflyerJsonProperty> properties)
        {
            var list = properties.ToList();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in list)
            {
                if (!seen.Add(property.Name)) throw new NightflyerJsonException("Duplicate JSON property.", duplicate: true);
            }
            return new NightflyerJsonNode(NightflyerJsonValueKind.Object, null, list, null);
        }

        internal static NightflyerJsonNode CreateArray(IEnumerable<NightflyerJsonNode> items) =>
            new(NightflyerJsonValueKind.Array, null, null, items.ToList());

        internal static NightflyerJsonNode CreateString(string value) =>
            new(NightflyerJsonValueKind.String, value, null, null);

        internal static NightflyerJsonNode CreateNumber(long value) =>
            new(NightflyerJsonValueKind.Number, value.ToString(System.Globalization.CultureInfo.InvariantCulture), null, null);

        public bool IsNull => Kind == NightflyerJsonValueKind.Null;

        /// <summary>The string value; null when this node is not a string.</summary>
        public string? StringValue => Kind == NightflyerJsonValueKind.String ? _text : null;

        /// <summary>The boolean value; null when this node is not true or false.</summary>
        public bool? BoolValue => Kind switch
        {
            NightflyerJsonValueKind.True => true,
            NightflyerJsonValueKind.False => false,
            _ => null,
        };

        /// <summary>Extracts the integer value. Decimals, exponents, and values outside the signed 64-bit range fail, keeping their Number kind.</summary>
        public bool TryGetInt64(out long value)
        {
            if (Kind != NightflyerJsonValueKind.Number || _text is null)
            {
                value = 0;
                return false;
            }
            return long.TryParse(_text, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out value);
        }

        public IReadOnlyList<NightflyerJsonProperty> Properties => _properties ?? (IReadOnlyList<NightflyerJsonProperty>)Array.Empty<NightflyerJsonProperty>();
        public IReadOnlyList<NightflyerJsonNode> Items => _items ?? (IReadOnlyList<NightflyerJsonNode>)Array.Empty<NightflyerJsonNode>();

        public bool TryGetProperty(string name, out NightflyerJsonNode value)
        {
            if (_properties is not null)
            {
                foreach (var property in _properties)
                {
                    if (string.Equals(property.Name, name, StringComparison.Ordinal))
                    {
                        value = property.Value;
                        return true;
                    }
                }
            }
            value = null!;
            return false;
        }

        public NightflyerJsonNode GetProperty(string name) =>
            TryGetProperty(name, out var value) ? value : throw new KeyNotFoundException($"Property '{name}' not found.");

        public static NightflyerJsonNode Parse(byte[] utf8)
        {
            // Strict UTF-8: invalid byte sequences (including unpaired surrogates) are malformed input.
            string text;
            try
            {
                text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(utf8);
            }
            catch (DecoderFallbackException exception)
            {
                throw new NightflyerJsonException(exception.Message);
            }
            var parser = new NightflyerJsonParser(text);
            var node = parser.ParseDocument();
            return node;
        }
    }

    internal sealed class NightflyerJsonParser
    {
        private readonly string _text;
        private int _position;
        private int _depth;

        private const int MaximumDepth = 32;

        public NightflyerJsonParser(string text)
        {
            _text = text;
        }

        public NightflyerJsonNode ParseDocument()
        {
            SkipWhitespace();
            var value = ParseValue();
            SkipWhitespace();
            if (_position != _text.Length) throw new NightflyerJsonException("Trailing content after the JSON document.");
            return value;
        }

        private NightflyerJsonNode ParseValue()
        {
            if (_position >= _text.Length) throw new NightflyerJsonException("The JSON document ended unexpectedly.");
            var character = _text[_position];
            switch (character)
            {
                case '{':
                    return ParseObject();
                case '[':
                    return ParseArray();
                case '"':
                    return NightflyerJsonNode.CreateString(ParseString());
                case 't':
                    ExpectLiteral("true");
                    return new NightflyerJsonNode(NightflyerJsonValueKind.True, null, null, null);
                case 'f':
                    ExpectLiteral("false");
                    return new NightflyerJsonNode(NightflyerJsonValueKind.False, null, null, null);
                case 'n':
                    ExpectLiteral("null");
                    return new NightflyerJsonNode(NightflyerJsonValueKind.Null, null, null, null);
                default:
                    if (character == '-' || (character >= '0' && character <= '9')) return ParseNumber();
                    throw new NightflyerJsonException("Unexpected character in the JSON document.");
            }
        }

        private NightflyerJsonNode ParseObject()
        {
            _position++; // consume '{'
            if (++_depth > MaximumDepth) throw new NightflyerJsonException("The JSON document nests deeper than 32 levels.");
            var properties = new List<NightflyerJsonProperty>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            SkipWhitespace();
            if (_position < _text.Length && _text[_position] == '}')
            {
                _position++;
                _depth--;
                return NightflyerJsonNode.CreateObject(properties);
            }
            while (true)
            {
                SkipWhitespace();
                if (_position >= _text.Length || _text[_position] != '"') throw new NightflyerJsonException("An object member name must be a string.");
                var name = ParseString();
                if (!seen.Add(name)) throw new NightflyerJsonException("Duplicate JSON property.", duplicate: true);
                SkipWhitespace();
                if (_position >= _text.Length || _text[_position] != ':') throw new NightflyerJsonException("An object member must be followed by ':'.");
                _position++;
                SkipWhitespace();
                properties.Add(new NightflyerJsonProperty(name, ParseValue()));
                SkipWhitespace();
                if (_position >= _text.Length) throw new NightflyerJsonException("The JSON document ended inside an object.");
                var separator = _text[_position++];
                if (separator == '}') break;
                if (separator != ',') throw new NightflyerJsonException("Object members must be separated by ','.");
            }
            _depth--;
            return NightflyerJsonNode.CreateObject(properties);
        }

        private NightflyerJsonNode ParseArray()
        {
            _position++; // consume '['
            if (++_depth > MaximumDepth) throw new NightflyerJsonException("The JSON document nests deeper than 32 levels.");
            var items = new List<NightflyerJsonNode>();
            SkipWhitespace();
            if (_position < _text.Length && _text[_position] == ']')
            {
                _position++;
                _depth--;
                return NightflyerJsonNode.CreateArray(items);
            }
            while (true)
            {
                SkipWhitespace();
                items.Add(ParseValue());
                SkipWhitespace();
                if (_position >= _text.Length) throw new NightflyerJsonException("The JSON document ended inside an array.");
                var separator = _text[_position++];
                if (separator == ']') break;
                if (separator != ',') throw new NightflyerJsonException("Array items must be separated by ','.");
            }
            _depth--;
            return NightflyerJsonNode.CreateArray(items);
        }

        private string ParseString()
        {
            _position++; // consume '"'
            var result = new StringBuilder();
            while (true)
            {
                if (_position >= _text.Length) throw new NightflyerJsonException("The JSON string ended unexpectedly.");
                var character = _text[_position++];
                if (character == '"') break;
                if (character == '\\')
                {
                    if (_position >= _text.Length) throw new NightflyerJsonException("The JSON string ended unexpectedly.");
                    var escape = _text[_position++];
                    switch (escape)
                    {
                        case '"': result.Append('"'); break;
                        case '\\': result.Append('\\'); break;
                        case '/': result.Append('/'); break;
                        case 'b': result.Append('\b'); break;
                        case 'f': result.Append('\f'); break;
                        case 'n': result.Append('\n'); break;
                        case 'r': result.Append('\r'); break;
                        case 't': result.Append('\t'); break;
                        case 'u':
                            if (_position + 4 > _text.Length) throw new NightflyerJsonException("The \\u escape is truncated.");
                            result.Append((char)ParseHex4(_text.Substring(_position, 4)));
                            _position += 4;
                            break;
                        default:
                            throw new NightflyerJsonException("Invalid escape sequence in the JSON string.");
                    }
                    continue;
                }
                if (character < 0x20) throw new NightflyerJsonException("Control characters must be escaped in JSON strings.");
                result.Append(character);
            }
            return result.ToString();
        }

        private int ParseHex4(string digits)
        {
            var value = 0;
            foreach (var digit in digits)
            {
                value <<= 4;
                if (digit >= '0' && digit <= '9') value |= digit - '0';
                else if (digit >= 'a' && digit <= 'f') value |= digit - 'a' + 10;
                else if (digit >= 'A' && digit <= 'F') value |= digit - 'A' + 10;
                else throw new NightflyerJsonException("Invalid hexadecimal digit in a \\u escape.");
            }
            return value;
        }

        private NightflyerJsonNode ParseNumber()
        {
            var start = _position;
            if (_text[_position] == '-') _position++;
            if (_position >= _text.Length) throw new NightflyerJsonException("The JSON number ended unexpectedly.");
            // JSON forbids leading zeros: "0" or "0.x" only.
            if (_text[_position] == '0')
            {
                _position++;
            }
            else if (_text[_position] >= '1' && _text[_position] <= '9')
            {
                while (_position < _text.Length && _text[_position] >= '0' && _text[_position] <= '9') _position++;
            }
            else
            {
                throw new NightflyerJsonException("Invalid JSON number.");
            }
            if (_position < _text.Length && _text[_position] >= '0' && _text[_position] <= '9')
                throw new NightflyerJsonException("JSON numbers cannot have leading zeros.");
            if (_position < _text.Length && _text[_position] == '.')
            {
                _position++;
                var fractionDigits = 0;
                while (_position < _text.Length && _text[_position] >= '0' && _text[_position] <= '9') { _position++; fractionDigits++; }
                if (fractionDigits == 0) throw new NightflyerJsonException("A JSON fraction must contain digits.");
            }
            if (_position < _text.Length && (_text[_position] == 'e' || _text[_position] == 'E'))
            {
                _position++;
                if (_position < _text.Length && (_text[_position] == '+' || _text[_position] == '-')) _position++;
                var exponentDigits = 0;
                while (_position < _text.Length && _text[_position] >= '0' && _text[_position] <= '9') { _position++; exponentDigits++; }
                if (exponentDigits == 0) throw new NightflyerJsonException("A JSON exponent must contain digits.");
            }
            var token = _text.Substring(start, _position - start);
            // long.TryParse decides integer representability; everything else
            // stays a Number that fails integer extraction.
            return new NightflyerJsonNode(NightflyerJsonValueKind.Number, token, null, null);
        }

        private void ExpectLiteral(string literal)
        {
            if (_position + literal.Length > _text.Length || _text.Substring(_position, literal.Length) != literal)
                throw new NightflyerJsonException("Invalid JSON literal.");
            _position += literal.Length;
        }

        private void SkipWhitespace()
        {
            while (_position < _text.Length)
            {
                var character = _text[_position];
                if (character == ' ' || character == '\t' || character == '\r' || character == '\n') _position++;
                else break;
            }
        }
    }

    /// <summary>Minimal-escaping JSON writer for protocol values the client constructs itself.</summary>
    internal static class NightflyerJsonWriter
    {
        /// <summary>Serializes a protocol value tree: null, bool, string, int, long, string arrays, ordered member lists, and pre-parsed nodes.</summary>
        public static byte[] SerializeToUtf8(object? value)
        {
            return Encoding.UTF8.GetBytes(Serialize(value));
        }

        public static string Serialize(object? value)
        {
            var builder = new StringBuilder();
            Write(builder, value);
            return builder.ToString();
        }

        private static void Write(StringBuilder builder, object? value)
        {
            switch (value)
            {
                case null:
                    builder.Append("null");
                    break;
                case bool boolean:
                    builder.Append(boolean ? "true" : "false");
                    break;
                case string text:
                    WriteString(builder, text);
                    break;
                case long number:
                    builder.Append(number.ToString(System.Globalization.CultureInfo.InvariantCulture));
                    break;
                case int number:
                    builder.Append(number.ToString(System.Globalization.CultureInfo.InvariantCulture));
                    break;
                case string[] strings:
                    WriteStringArray(builder, strings);
                    break;
                case IReadOnlyList<string> stringList:
                    WriteStringArray(builder, stringList);
                    break;
                case NightflyerJsonNode node:
                    WriteNode(builder, node);
                    break;
                case IReadOnlyList<KeyValuePair<string, object?>> members:
                    builder.Append('{');
                    for (var index = 0; index < members.Count; index++)
                    {
                        if (index > 0) builder.Append(',');
                        WriteString(builder, members[index].Key);
                        builder.Append(':');
                        Write(builder, members[index].Value);
                    }
                    builder.Append('}');
                    break;
                default:
                    throw new NightflyerJsonException("Unsupported value in the Nightflyer JSON writer.");
            }
        }

        private static void WriteStringArray(StringBuilder builder, IReadOnlyList<string> values)
        {
            builder.Append('[');
            for (var index = 0; index < values.Count; index++)
            {
                if (index > 0) builder.Append(',');
                WriteString(builder, values[index]);
            }
            builder.Append(']');
        }

        private static void WriteNode(StringBuilder builder, NightflyerJsonNode node)
        {
            switch (node.Kind)
            {
                case NightflyerJsonValueKind.Object:
                    builder.Append('{');
                    var properties = node.Properties;
                    for (var index = 0; index < properties.Count; index++)
                    {
                        if (index > 0) builder.Append(',');
                        WriteString(builder, properties[index].Name);
                        builder.Append(':');
                        WriteNode(builder, properties[index].Value);
                    }
                    builder.Append('}');
                    break;
                case NightflyerJsonValueKind.Array:
                    builder.Append('[');
                    var items = node.Items;
                    for (var index = 0; index < items.Count; index++)
                    {
                        if (index > 0) builder.Append(',');
                        WriteNode(builder, items[index]);
                    }
                    builder.Append(']');
                    break;
                case NightflyerJsonValueKind.String:
                    WriteString(builder, node.StringValue!);
                    break;
                case NightflyerJsonValueKind.Number:
                    if (!node.TryGetInt64(out var integer))
                        throw new NightflyerJsonException("A parsed protocol number lost its token text.");
                    builder.Append(integer.ToString(System.Globalization.CultureInfo.InvariantCulture));
                    break;
                case NightflyerJsonValueKind.True:
                    builder.Append("true");
                    break;
                case NightflyerJsonValueKind.False:
                    builder.Append("false");
                    break;
                case NightflyerJsonValueKind.Null:
                    builder.Append("null");
                    break;
                default:
                    throw new NightflyerJsonException("Unsupported node in the Nightflyer JSON writer.");
            }
        }

        private static void WriteString(StringBuilder builder, string value)
        {
            builder.Append('"');
            foreach (var character in value)
            {
                switch (character)
                {
                    case '"': builder.Append("\\\""); break;
                    case '\\': builder.Append("\\\\"); break;
                    case '\b': builder.Append("\\b"); break;
                    case '\t': builder.Append("\\t"); break;
                    case '\n': builder.Append("\\n"); break;
                    case '\f': builder.Append("\\f"); break;
                    case '\r': builder.Append("\\r"); break;
                    default:
                        // Matches the encoder used by the other Nightflyer
                        // clients: only control characters are escaped.
                        if (character < 0x20)
                            builder.Append("\\u").Append(((int)character).ToString("x4", System.Globalization.CultureInfo.InvariantCulture));
                        else
                            builder.Append(character);
                        break;
                }
            }
            builder.Append('"');
        }
    }
}
