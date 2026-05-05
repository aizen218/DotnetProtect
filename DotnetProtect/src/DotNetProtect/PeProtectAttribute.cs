namespace DotNetProtect;

/// <summary>
/// When placed on the assembly, the weaver strips cosmetic metadata attributes
/// (company, product, title, configuration, file and informational version) and applies
/// binary-level PE hardening: randomises the PE timestamp and zeros the debug directory
/// entry so PDB-path references and reproducibility records are not accessible to static tools.
/// </summary>
[AttributeUsage(AttributeTargets.Assembly, Inherited = false, AllowMultiple = false)]
public sealed class PeProtectAttribute : Attribute
{
}
