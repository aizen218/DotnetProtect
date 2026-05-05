namespace DotNetProtect;

/// <summary>
/// Marks a method where the build-time weaver replaces every <c>ldc.i4*</c> and <c>ldc.i8</c> with XOR-encrypted
/// blobs decoded at runtime via <c>ConstantDecrypt</c> (AOT-friendly). <see cref="bool"/> literals compile to
/// <c>ldc.i4.0</c>/<c>ldc.i4.1</c> and are included in that pass (there is no separate boolean <c>ldc</c> opcode).
/// Floating-point literals (<c>ldc.r4</c>/<c>ldc.r8</c>) are also rewritten into XOR blobs and decoded through
/// <c>ConstantDecrypt.FromXorSingle</c>/<c>ConstantDecrypt.FromXorDouble</c>.
/// Raw byte buffers are not woven automatically; use <see cref="DotNetProtect.Runtime.ConstantDecrypt.FromXorBytes"/> with your own blob + key if needed.
/// You can stack this with <see cref="StringEncryptAttribute"/> on the same method; both passes run.
/// </summary>
[AttributeUsage(AttributeTargets.Method, Inherited = false, AllowMultiple = false)]
public sealed class ObfuscateControlFlowAttribute : Attribute
{
}
