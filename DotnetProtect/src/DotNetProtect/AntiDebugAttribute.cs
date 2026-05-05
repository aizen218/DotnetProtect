namespace DotNetProtect;

/// <summary>
/// <para>Auto-injects a debugger / tracer check at the start of every eligible method.</para>
/// <para><b>On an assembly:</b> every eligible method in every type across the entire assembly
/// gets the prologue — equivalent to placing <see cref="InjectAntiDebugAttribute"/> on each type.</para>
/// <para><b>On a class or struct:</b> every eligible method (non-constructor, non-special-name,
/// has a body) gets the prologue.</para>
/// <para><b>On a method:</b> only that method gets the prologue.</para>
/// <para>Members decorated with <see cref="PreserveAttribute"/> are always skipped.
/// Constructors, abstract, extern, and P/Invoke methods are skipped automatically.</para>
/// <para>Stack with <see cref="StringEncryptAttribute"/> or <see cref="ObfuscateControlFlowAttribute"/>
/// for layered protection.</para>
/// </summary>
[AttributeUsage(
    AttributeTargets.Assembly | AttributeTargets.Method |
    AttributeTargets.Class   | AttributeTargets.Struct,
    Inherited = false, AllowMultiple = false)]
public sealed class AntiDebugAttribute : Attribute
{
}
