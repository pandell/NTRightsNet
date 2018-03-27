using System;
using System.Reflection;
using System.Resources;
using System.Runtime.InteropServices;

[assembly: AssemblyCompany("Pandell Technology Corporation")]
[assembly: AssemblyCopyright("Copyright (C) 2002-2018 Pandell Technology Corporation. All rights reserved.")]
[assembly: AssemblyTrademark("Pandell Lithium (PLI) is a registered trademark of Pandell Technology Corporation in Canada and/or other countries.")]
[assembly: AssemblyCulture("")]
[assembly: NeutralResourcesLanguage("en", UltimateResourceFallbackLocation.MainAssembly)]

[assembly: AssemblyVersion("1.0.0.0")] // for more discussion on versioning see http://stackoverflow.com/questions/62353/what-are-the-best-practices-for-using-assembly-attributes (and its followup)
[assembly: AssemblyFileVersion("1.0.0.7")]
[assembly: AssemblyInformationalVersion("1.0.0")]
[assembly: AssemblyProduct("NTRightsNet v1.0.0 "
#if DEBUG
    + "(debug)"
#else
    + "(release)"
#endif
)]

[assembly: AssemblyConfiguration(
#if DEBUG
    "DEBUG"
#else
    "RELEASE"
#endif
)]

[assembly: AssemblyTitle("NTRightsNet - Gets or sets privileges for the specified account.")]
[assembly: AssemblyDescription("NTRightsNet - Gets or sets privileges for the specified account.")]
[assembly: CLSCompliant(true)]
[assembly: ComVisible(false)]
