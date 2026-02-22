using System.Text.Json;
using Kusto.Language;
using Kusto.Language.Syntax;

/// <summary>
/// KQL Syntax Validator — reads a manifest of extracted KQL files
/// and validates each one using the official Kusto.Language parser.
///
/// Input:  path to manifest.json (produced by validate_kql.py)
/// Output: JSON to stdout with validation results
///
/// Exit codes:
///   0  All queries passed
///   1  One or more queries have syntax errors
///   2  Script-level error
/// </summary>

if (args.Length < 1)
{
    Console.Error.WriteLine("Usage: KqlValidator <manifest.json>");
    return 2;
}

var manifestPath = args[0];
if (!File.Exists(manifestPath))
{
    Console.Error.WriteLine($"Manifest file not found: {manifestPath}");
    return 2;
}

var manifestJson = File.ReadAllText(manifestPath);
var manifest = JsonSerializer.Deserialize<List<ManifestEntry>>(manifestJson);

if (manifest is null || manifest.Count == 0)
{
    Console.Error.WriteLine("Manifest is empty or could not be parsed.");
    return 2;
}

var errors = new List<ValidationError>();
int passed = 0;

foreach (var entry in manifest)
{
    if (!File.Exists(entry.kql_file))
    {
        errors.Add(new ValidationError
        {
            id = entry.id,
            file = entry.file,
            block_index = entry.block_index,
            line = entry.line,
            message = $"KQL file not found: {entry.kql_file}"
        });
        continue;
    }

    var kqlCode = File.ReadAllText(entry.kql_file);

    // Parse as a KQL query using the official parser
    var parsed = KustoCode.Parse(kqlCode);

    // Collect diagnostics (syntax errors)
    var diagnostics = parsed.GetDiagnostics()
        .Where(d => d.Severity == "Error")
        .ToList();

    if (diagnostics.Count == 0)
    {
        passed++;
    }
    else
    {
        // Combine all error messages for this block
        var messages = diagnostics
            .Select(d =>
            {
                var position = GetLineAndColumn(kqlCode, d.Start);
                return $"[Ln {position.Line}, Col {position.Col}] {d.Message}";
            })
            .ToList();

        errors.Add(new ValidationError
        {
            id = entry.id,
            file = entry.file,
            block_index = entry.block_index,
            line = entry.line,
            message = string.Join("; ", messages)
        });
    }
}

// Output results as JSON
var results = new
{
    total = manifest.Count,
    passed,
    failed = errors.Count,
    errors
};

var options = new JsonSerializerOptions { WriteIndented = true };
Console.WriteLine(JsonSerializer.Serialize(results, options));

return errors.Count > 0 ? 1 : 0;

// --- Helper types and methods ---

static (int Line, int Col) GetLineAndColumn(string text, int offset)
{
    if (offset < 0 || offset >= text.Length)
        return (1, 1);

    int line = 1;
    int col = 1;
    for (int i = 0; i < offset; i++)
    {
        if (text[i] == '\n')
        {
            line++;
            col = 1;
        }
        else
        {
            col++;
        }
    }
    return (line, col);
}

record ManifestEntry
{
    public int id { get; init; }
    public string file { get; init; } = "";
    public int block_index { get; init; }
    public int line { get; init; }
    public string kql_file { get; init; } = "";
}

record ValidationError
{
    public int id { get; init; }
    public string file { get; init; } = "";
    public int block_index { get; init; }
    public int line { get; init; }
    public string message { get; init; } = "";
}
