namespace DotNetProtect;

/// <summary>
/// <para>Auto-injects a debugger / tracer check at the start of the marked method:
/// the weaver inserts a call to <see cref="DotNetProtect.Runtime.AntiDebug.LikelyUnderDebugger"/>
/// followed by <c>Environment.Exit</c> when the check returns true.</para>
/// <para><b>On a class or struct:</b> every eligible method (non-constructor, non-special-name,
/// has a body) gets the prologue. Members with <see cref="PreserveAttribute"/> are skipped.</para>
/// <para>The runtime helper is used directly — no dependency on the
/// <c>DOTNETPROTECT_ANTIDEBUG</c> compile constant. Stack with <see cref="StringEncryptAttribute"/>
/// or <see cref="ObfuscateControlFlowAttribute"/> for layered protection.</para>
/// <para>The injection runs <i>before</i> string / constant obfuscation, so the injected
/// <c>ldc.i4</c> exit code is itself obfuscated when the method also has
/// <c>[ObfuscateControlFlow]</c> (or its declaring type has <c>[ProtectMembers]</c>).</para>
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class | AttributeTargets.Struct,
    Inherited = false, AllowMultiple = false)]
public sealed class InjectAntiDebugAttribute : Attribute
{
}
