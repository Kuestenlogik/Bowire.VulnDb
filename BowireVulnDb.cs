// Copyright 2026 Küstenlogik
// SPDX-License-Identifier: Apache-2.0

using System.Reflection;

namespace Kuestenlogik.Bowire.VulnDb;

/// <summary>
/// Typed accessor for the curated Bowire security-template corpus.
/// Templates ship as manifest resources inside the
/// <c>Kuestenlogik.Bowire.VulnDb</c> NuGet — call <see cref="GetAllTemplateIds"/>
/// to enumerate them, then <see cref="ReadTemplate(string)"/> to pull
/// the JSON content. The <c>templates-index.json</c> sidecar (also
/// embedded) carries the per-template metadata (protocol, owaspApi,
/// severity, &amp;c) so consumers don't need to parse every template
/// to filter.
/// </summary>
public static class BowireVulnDbCatalogue
{
    private static readonly Assembly _asm = typeof(BowireVulnDbCatalogue).Assembly;
    private const string ResourcePrefix = "Kuestenlogik.Bowire.VulnDb.templates.";

    /// <summary>
    /// Enumerate every template's logical id as exposed by the
    /// embedded resource naming. Example: a template at
    /// <c>templates/graphql/introspection-enabled.json</c> shows up
    /// as <c>graphql/introspection-enabled.json</c>.
    /// </summary>
    public static IEnumerable<string> GetAllTemplateIds()
    {
        foreach (var name in _asm.GetManifestResourceNames())
        {
            if (!name.StartsWith(ResourcePrefix, StringComparison.Ordinal)) continue;
            // Strip the prefix and convert the LogicalName's dot-
            // path back to a / separator so callers see the file-
            // system shape they'd expect.
            var rel = name.Substring(ResourcePrefix.Length);
            // Reverse the LogicalName dotting: last dot is the
            // extension boundary, every dot before it is a folder.
            var lastDot = rel.LastIndexOf('.');
            if (lastDot < 0) { yield return rel; continue; }
            var path = rel.Substring(0, lastDot).Replace('.', '/');
            var ext = rel.Substring(lastDot);
            yield return path + ext;
        }
    }

    /// <summary>
    /// Open a template by its logical id (e.g.
    /// <c>graphql/introspection-enabled.json</c>) and return the raw
    /// JSON content. Throws <see cref="FileNotFoundException"/> when
    /// the id doesn't match any embedded template.
    /// </summary>
    public static string ReadTemplate(string templateId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(templateId);
        using var s = OpenTemplate(templateId);
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }

    /// <summary>
    /// Stream the raw template JSON. Caller owns the stream and
    /// must dispose it.
    /// </summary>
    public static Stream OpenTemplate(string templateId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(templateId);
        // Translate the file-shape id back to the LogicalName
        // dot-path the embedder used.
        var lastSlash = templateId.LastIndexOf('/');
        string logicalName;
        if (lastSlash < 0)
        {
            logicalName = ResourcePrefix + templateId;
        }
        else
        {
            var folders = templateId.Substring(0, lastSlash).Replace('/', '.');
            var file = templateId.Substring(lastSlash + 1);
            logicalName = ResourcePrefix + folders + "." + file;
        }
        var s = _asm.GetManifestResourceStream(logicalName)
            ?? throw new FileNotFoundException(
                "No Bowire VulnDb template embedded under id: " + templateId,
                templateId);
        return s;
    }

    /// <summary>
    /// Read the bundled <c>templates-index.json</c> sidecar that
    /// summarises every template's metadata (id, protocol, severity,
    /// owaspApi). Returns <c>null</c> when the index resource is not
    /// present — older builds of the package may ship without it.
    /// </summary>
    public static string? ReadIndex()
    {
        using var s = _asm.GetManifestResourceStream(
            "Kuestenlogik.Bowire.VulnDb.templates-index.json");
        if (s is null) return null;
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }
}
