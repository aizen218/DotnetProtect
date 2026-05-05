namespace DotNetProtect;

/// <summary>
/// When placed on the assembly, the weaver embeds a build-time random seed and an
/// SHA-256 digest over <c>seed || concat(all FieldRVA blob payloads on the blob holder,
/// sorted by field name)</c>. At runtime a module initializer recomputes the hash from
/// live blob bytes (no reflection). Tampering with any woven blob invalidates the digest.
/// </summary>
[AttributeUsage(AttributeTargets.Assembly, Inherited = false, AllowMultiple = false)]
public sealed class VerifyIntegrityAttribute : Attribute
{
}
