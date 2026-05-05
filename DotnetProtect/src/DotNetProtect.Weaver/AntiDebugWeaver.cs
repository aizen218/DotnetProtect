using Mono.Cecil;
using Mono.Cecil.Cil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    /// <summary>
    /// Injects at the very start of <paramref name="method"/>:
    /// <code>
    ///   if (AntiDebug.LikelyUnderDebugger())
    ///       Environment.Exit(0);
    /// </code>
    /// Skips constructors / static constructors / special-name methods / abstract / extern.
    /// Idempotent: detects an existing injection (call to <c>LikelyUnderDebugger</c> within
    /// the first few instructions) and returns false in that case.
    /// </summary>
    private static bool InjectAntiDebugPrologue(MethodDefinition method, AntiDebugInjector inj)
    {
        if (!method.HasBody) return false;
        if (method.IsConstructor) return false;
        if (method.Name == ".cctor") return false;
        if (method.IsAbstract || (method.ImplAttributes & MethodImplAttributes.InternalCall) != 0) return false;
        if (method.IsPInvokeImpl) return false;

        // Idempotency: if the first few instructions already call LikelyUnderDebugger, skip.
        var body = method.Body;
        for (var i = 0; i < Math.Min(4, body.Instructions.Count); i++)
        {
            var ins = body.Instructions[i];
            if (ins.OpCode.Code is Code.Call or Code.Callvirt &&
                ins.Operand is MethodReference mr &&
                mr.FullName == inj.LikelyUnderDebugger.FullName)
                return false;
        }

        if (body.Instructions.Count == 0) return false;

        var il    = body.GetILProcessor();
        var first = body.Instructions[0];

        // Use a NOP as the brfalse target rather than `first`. Subsequent passes
        // (string encrypt, CF obfuscate) replace instructions in-place — if `first`
        // is itself a ldstr / ldc.* it gets removed, leaving the brfalse pointing
        // at a detached instruction. The NOP is a stable anchor neither pass touches.
        var continueAnchor = Instruction.Create(OpCodes.Nop);
        il.InsertBefore(first, continueAnchor);

        var callCheck = Instruction.Create(OpCodes.Call,    inj.LikelyUnderDebugger);
        var brfalse   = Instruction.Create(OpCodes.Brfalse, continueAnchor);
        var loadCode  = Instruction.Create(OpCodes.Ldc_I4_0);
        var callExit  = Instruction.Create(OpCodes.Call,    inj.EnvironmentExit);

        il.InsertBefore(continueAnchor, callCheck);
        il.InsertBefore(continueAnchor, brfalse);
        il.InsertBefore(continueAnchor, loadCode);
        il.InsertBefore(continueAnchor, callExit);

        RecomputeBody(method);
        return true;
    }
}
