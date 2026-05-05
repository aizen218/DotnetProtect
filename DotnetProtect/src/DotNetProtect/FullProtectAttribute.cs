namespace DotNetProtect;

/// <summary>
/// Applied to a <c>class</c> or <c>struct</c>: the weaver applies all three IL-level protections
/// to every eligible method — string encryption, primitive-constant obfuscation, and anti-debugger
/// prologue injection — and string encryption to every eligible <c>string</c> field.
/// <para>
/// Equivalent to stacking <see cref="ProtectMembersAttribute"/> and <see cref="InjectAntiDebugAttribute"/>
/// on the same type without having to write both.
/// </para>
/// <para>
/// Members decorated with <see cref="PreserveAttribute"/> are excluded from all passes.
/// Constructors, special-name methods, and the assembly entry point are skipped automatically.
/// </para>
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, Inherited = false, AllowMultiple = false)]
public sealed class FullProtectAttribute : Attribute
{
}
