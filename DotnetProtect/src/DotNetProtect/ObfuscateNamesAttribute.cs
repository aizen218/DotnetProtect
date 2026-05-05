namespace DotNetProtect;

/// <summary>
/// Opt-in per-element name mangling, independent of the <c>--rename-private-marked</c> and
/// <c>--full-metadata</c> CLI flags.
/// <list type="bullet">
///   <item><term>On a type</term><description>
///     The type itself (if non-public) and all of its eligible non-public methods, fields,
///     and properties are renamed to opaque identifiers at weave time.
///     Individual members can opt out with <see cref="PreserveAttribute"/>.
///   </description></item>
///   <item><term>On a method or field</term><description>
///     Only that member is renamed (if it is non-public and not a special-name / entry point).
///   </description></item>
///   <item><term>On a property</term><description>
///     The property and its <c>get_</c> / <c>set_</c> accessors are renamed together
///     (same rules as <c>--full-metadata</c> property handling).
///   </description></item>
/// </list>
/// <para>Members decorated with <see cref="PreserveAttribute"/> are always excluded.</para>
/// </summary>
[AttributeUsage(
    AttributeTargets.Class | AttributeTargets.Struct |
    AttributeTargets.Method | AttributeTargets.Field | AttributeTargets.Property,
    Inherited = false, AllowMultiple = false)]
public sealed class ObfuscateNamesAttribute : Attribute
{
}
