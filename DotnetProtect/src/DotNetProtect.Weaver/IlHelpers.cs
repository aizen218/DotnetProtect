using Mono.Cecil;
using Mono.Cecil.Cil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    private static void EmitLdcI4(ILProcessor il, int value)
    {
        switch (value)
        {
            case 0: il.Emit(OpCodes.Ldc_I4_0); break;
            case 1: il.Emit(OpCodes.Ldc_I4_1); break;
            case 2: il.Emit(OpCodes.Ldc_I4_2); break;
            case 3: il.Emit(OpCodes.Ldc_I4_3); break;
            case 4: il.Emit(OpCodes.Ldc_I4_4); break;
            case 5: il.Emit(OpCodes.Ldc_I4_5); break;
            case 6: il.Emit(OpCodes.Ldc_I4_6); break;
            case 7: il.Emit(OpCodes.Ldc_I4_7); break;
            case 8: il.Emit(OpCodes.Ldc_I4_8); break;
            case >= -128 and <= 127:
                il.Emit(OpCodes.Ldc_I4_S, (sbyte)value);
                break;
            default:
                il.Emit(OpCodes.Ldc_I4, value);
                break;
        }
    }

    private static void RecomputeBody(MethodDefinition method)
    {
        if (!method.HasBody)
            return;

        method.Body.InitLocals = true;
        // Cecil 0.11 uses MaxStackSize; leave headroom for injected calls.
        if (method.Body.MaxStackSize < 64)
            method.Body.MaxStackSize = 64;
    }

    private static void ReplaceInstructions(ILProcessor il, Instruction target, Instruction[] sequence)
    {
        if (sequence.Length == 0)
        {
            il.Remove(target);
            return;
        }

        Instruction? previous = null;
        foreach (var next in sequence)
        {
            if (previous is null)
                il.InsertBefore(target, next);
            else
                il.InsertAfter(previous, next);

            previous = next;
        }

        il.Remove(target);
    }
}
