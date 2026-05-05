namespace DotNetProtect;

/// <summary>
/// When placed on the assembly, the weaver injects a module initializer that compares a short
/// window of the main executable mapping against the same bytes read from on-disk <see cref="Environment.ProcessPath"/>.
/// This detects straightforward in-memory patching of native AOT code pages.
/// </summary>
[AttributeUsage(AttributeTargets.Assembly, Inherited = false, AllowMultiple = false)]
public sealed class VerifyNativeExecutableCoherencyAttribute : Attribute
{
    /// <param name="mappedByteCount">Maximum bytes to hash from the first RX mapping (capped in runtime).</param>
    public VerifyNativeExecutableCoherencyAttribute(int mappedByteCount = 512) =>
        MappedByteCount = mappedByteCount;

    public int MappedByteCount { get; }
}
