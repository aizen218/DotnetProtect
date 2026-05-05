namespace DotNetProtect;

/// <summary>
/// Opts this member or type out of all DotNetProtect weaving and metadata renaming.
/// <list type="bullet">
///   <item><term>On a type</term><description>
///     Prevents renaming of the type itself and suppresses
///     <see cref="ProtectMembersAttribute"/> / class-level <see cref="StringEncryptAttribute"/>
///     propagation to its members. Per-member <c>[StringEncrypt]</c> or <c>[ObfuscateControlFlow]</c>
///     attributes on individual methods/fields are still honoured.
///   </description></item>
///   <item><term>On a method or field</term><description>
///     Prevents string encryption, constant obfuscation, and metadata renaming for that member,
///     even when the declaring type has <see cref="ProtectMembersAttribute"/> or a class-level
///     <see cref="StringEncryptAttribute"/>.
///   </description></item>
/// </list>
/// </summary>
[AttributeUsage(
    AttributeTargets.Method | AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Class | AttributeTargets.Struct,
    Inherited = false,
    AllowMultiple = false)]
public sealed class PreserveAttribute : Attribute
{
}
