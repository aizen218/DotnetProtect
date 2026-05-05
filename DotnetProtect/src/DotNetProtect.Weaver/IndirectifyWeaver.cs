using Mono.Cecil;
using Mono.Cecil.Cil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    private static CallSite CreateIndirectCallSite(ModuleDefinition module, MethodReference callee)
    {
        var cs = new CallSite(module.ImportReference(callee.ReturnType));
        cs.HasThis = callee.HasThis;
        cs.ExplicitThis = callee.ExplicitThis;
        foreach (var p in callee.Parameters)
            cs.Parameters.Add(new ParameterDefinition(p.Name, p.Attributes, module.ImportReference(p.ParameterType)));
        return cs;
    }

    private static bool IndirectifySomeCallsInMethod(ModuleDefinition module, MethodDefinition method)
    {
        if (!method.HasBody || method.Body.Instructions.Count < 2 || method.Body.HasExceptionHandlers)
            return false;

        var body = method.Body;
        var il = body.GetILProcessor();
        var budget = 8;
        var any = false;

        while (budget > 0)
        {
            Instruction[] snapshot = body.Instructions.ToArray();
            var progressed = false;
            for (var i = 0; i < snapshot.Length; i++)
            {
                var ins = snapshot[i];
                if (ins.OpCode != OpCodes.Call)
                    continue;

                if (i > 0 && IsIndirectCallIncompatiblePrefix(snapshot[i - 1].OpCode))
                    continue;

                if (ins.Operand is not MethodReference callee)
                    continue;

                var resolved = callee.Resolve();
                if (resolved is null || resolved.IsPInvokeImpl || resolved.IsAbstract || resolved.IsConstructor)
                    continue;
                if (resolved.Module != module)
                    continue;
                if (callee.ContainsGenericParameter)
                    continue;

                if (callee.HasThis)
                {
                    var decl = callee.DeclaringType.Resolve();
                    if (decl?.IsValueType == true)
                        continue;
                }

                var ns = callee.DeclaringType.Namespace ?? "";
                if (ns.StartsWith("DotNetProtect.Runtime", StringComparison.Ordinal))
                    continue;

                // Skip generated infrastructure in the blob holder (blob/key methods use
                // RuntimeHelpers.InitializeArray; calling them via calli causes JIT issues).
                if (ns == "" && callee.DeclaringType.Name == BlobHolderTypeName)
                    continue;

                var skip = false;
                foreach (var p in callee.Parameters)
                {
                    if (p.ParameterType.ContainsGenericParameter)
                    {
                        skip = true;
                        break;
                    }
                }

                if (skip || callee.ReturnType.ContainsGenericParameter)
                    continue;

                var callSite = CreateIndirectCallSite(module, callee);
                var ldftn = Instruction.Create(OpCodes.Ldftn, callee);
                var calli = Instruction.Create(OpCodes.Calli, callSite);
                il.Replace(ins, ldftn);
                il.InsertAfter(ldftn, calli);
                any = true;
                budget--;
                progressed = true;
                break;
            }

            if (!progressed)
                break;
        }

        if (any)
            RecomputeBody(method);

        return any;
    }

    private static bool IsIndirectCallIncompatiblePrefix(OpCode op) =>
        op == OpCodes.Tail || op == OpCodes.Constrained || op == OpCodes.Readonly || op == OpCodes.Volatile;
}
