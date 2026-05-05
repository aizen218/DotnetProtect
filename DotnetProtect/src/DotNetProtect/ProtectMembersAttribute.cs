namespace DotNetProtect;

/// <summary>
/// Applied to a <c>class</c> or <c>struct</c>: the weaver treats every eligible method as if it has both
/// <see cref="StringEncryptAttribute"/> and <see cref="ObfuscateControlFlowAttribute"/>, and every eligible
/// <c>string</c> field (non-const, non-readonly-ref) as if it has <see cref="StringEncryptAttribute"/>.
/// <para>
/// Members decorated with <see cref="PreserveAttribute"/> are excluded from all passes.
/// </para>
/// <para>
/// Stacking per-member <c>[StringEncrypt]</c> / <c>[ObfuscateControlFlow]</c> attributes on top of this is
/// safe — both passes are idempotent and run only once per member.
/// </para>
/// <para>
/// Ineligible methods (constructors with <c>IsSpecialName</c>, compiler-generated state-machine methods,
/// the assembly entry point) are automatically skipped by the weaver.
/// </para>
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, Inherited = false, AllowMultiple = false)]
public sealed class ProtectMembersAttribute : Attribute
{
}
