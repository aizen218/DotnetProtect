namespace DotNetProtect;

/// <summary>
/// <para><b>On a method:</b> every <c>ldstr</c> in that method is rewritten to AES blobs + runtime decrypt.
/// Stack with <see cref="ObfuscateControlFlowAttribute"/> on the same method if you want both string protection and literal hiding.</para>
/// <para><b>On a field:</b> must be <c>string</c> (not <c>const string</c> — those live only in metadata constants).
/// Use <c>static readonly string x = "...";</c> or an instance field with <c>= "...";</c> so the compiler emits
/// <c>ldstr</c> + <c>stsfld</c>/<c>stfld</c> in <c>.cctor</c> or <c>.ctor</c>, which the weaver can replace.</para>
/// <para><b>Resx / resources:</b> strings embedded in <c>.resources</c> stay plaintext unless you surface them through a <c>[StringEncrypt]</c> method
/// (e.g. map keys to literals in IL) or avoid resx for secrets.</para>
/// <para><b>On a class or struct:</b> every eligible method in the type is treated as if it individually has <c>[StringEncrypt]</c>.
/// Members decorated with <see cref="PreserveAttribute"/> are skipped.
/// Combine with <see cref="ProtectMembersAttribute"/> when you also want constant obfuscation at class level.</para>
/// <para><b>Exceptions / logs:</b> text in <c>throw</c> / logging in a marked method is still woven from <c>ldstr</c>; avoid leaking structure via <c>nameof</c> in sensitive builds.</para>
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Field | AttributeTargets.Class | AttributeTargets.Struct, Inherited = false, AllowMultiple = false)]
public sealed class StringEncryptAttribute : Attribute
{
}
