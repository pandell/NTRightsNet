using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

using JetBrains.Annotations;

using Microsoft.Win32.SafeHandles;

namespace NTRightsNet
{

    /// <summary>
    /// NTRightsNet: command-line application to get,
    /// add or remove rights for the specified account
    /// </summary>
    /// <remarks>
    /// Partially inspired by
    /// https://stefsewell.com/2010/10/10/accessing-the-lsa-from-managed-code/ .
    /// </remarks>
    internal static class Program
    {

        /// <summary>
        /// Main entry point for NTRightsNet application.
        /// </summary>
        public static int Main([CanBeNull, ItemCanBeNull] string[] args)
        {
            // determine command to run
            var sanitizedArgs = args?.Select(a => a?.Trim() ?? string.Empty).ToArray() ?? new string[0];
            var commandSpec = sanitizedArgs.Length < 1 ? string.Empty : sanitizedArgs[0];
            if (!Program.AllCommands.TryGetValue(commandSpec, out var command)) { command = Program.CommandNotFound; }

            // run command and display its result
            var result = command(args);
            switch (result)
            {
                case Success<string> s:
                    s.Value.WriteToConsoleWithColour();
                    Console.WriteLine();
                    return 0;

                case Failure<string> e:
                    $"&darkRed;Error: &red;{e.Message}\n".WriteToConsoleWithColour();
                    return 1;

                default:
                    "&darkRed;Unknown error\n".WriteToConsoleWithColour();
                    return 2;
            }
        }



        //**************************************************
        //* Private
        //**************************************************

        //--------------------------------------------------
        /// <summary>
        /// Defines recognized commands.
        /// </summary>
        private static readonly Dictionary<string, Func<string[], Result<string>>> AllCommands = new Dictionary<string, Func<string[], Result<string>>>(StringComparer.OrdinalIgnoreCase)
        {
            { string.Empty, Program.CommandUsage },
            { "help", Program.CommandUsage },
            { "--help", Program.CommandUsage },
            { "-h", Program.CommandUsage },
            { "/h", Program.CommandUsage },
            { "-?", Program.CommandUsage },
            { "/?", Program.CommandUsage },

            { "version", Program.CommandGetVersion },
            { "--version", Program.CommandGetVersion },
            { "-v", Program.CommandGetVersion },

            { "get", Program.CommandGetRights },

            { "add", Program.CommandAddRights },

            { "remove", Program.CommandRemoveRights }
        };


        //--------------------------------------------------
        private const string AllCommandsUsage = "&darkGray;Gets, adds or removes rights for the specified account.\n"
            + "Usage:\n"
            + "  NTRightsNet help\n"
            + "  NTRightsNet version\n"
            + "  NTRightsNet get [username]\n"
            + "  NTRightsNet add [username] [semicolonSeparatedRights]\n"
            + "  NTRightsNet remove [username] [--all|semicolonSeparatedRights]";


        //--------------------------------------------------
        /// <summary>
        /// Adds rights for the specified user.
        /// </summary>
        [NotNull] private static Result<string> CommandAddRights([NotNull, ItemNotNull] string[] args)
        {
            // verify arguments
            if (args.Length != 3)
            {
                return new Failure<string>($"Expected exactly 2 parameters, username and semicolonSeparatedRights\n\n{Program.AllCommandsUsage}");
            }

            // verify that the specified account exists
            var sid = new byte[1024];
            var sidSize = sid.Length;
            var domainName = new StringBuilder(1024);
            var domainNameSize = domainName.Capacity;
            var accountType = 0;
            if (!NativeMethods.LookupAccountName(string.Empty, args[1], sid, ref sidSize, domainName, ref domainNameSize, ref accountType)) // inspired by "System.Environment.UserDomainName"
            {
                return new Failure<string>("Unknown account", Marshal.GetLastWin32Error());
            }

            // open LSA policy
            var objectAttributes = default(NativeMethods.LSA_OBJECT_ATTRIBUTES);
            var policyStatus = NativeMethods.LsaNtStatusToWinError(
                NativeMethods.LsaOpenPolicy(null, ref objectAttributes, NativeMethods.LSA_POLICY.POLICY_LOOKUP_NAMES | NativeMethods.LSA_POLICY.POLICY_CREATE_ACCOUNT, out var policyHandle));
            if (policyStatus != 0)
            {
                return new Failure<string>("Unable to open LSA policy", policyStatus);
            }

            // set user's rights
            using (policyHandle)
            {
                var rights = args[2]
                    .Split(';')
                    .Select(p => p.Trim())
                    .Where(p => !string.IsNullOrEmpty(p))
                    .Select(p => new NativeMethods.LSA_UNICODE_STRING
                    {
                        Buffer = Marshal.StringToHGlobalUni(p),
                        Length = (ushort)(p.Length * UnicodeEncoding.CharSize),
                        MaximumLength = (ushort)((p.Length + 1) * UnicodeEncoding.CharSize)
                    })
                    .ToArray();

                if (rights.Length == 0)
                {
                    return new Failure<string>("No rights were specified");
                }

                var addStatus = NativeMethods.LsaNtStatusToWinError(
                    NativeMethods.LsaAddAccountRights(policyHandle, sid, rights, (uint)rights.Length));

                foreach (var right in rights) // release marshaled right strings
                {
                    Marshal.FreeHGlobal(right.Buffer);
                }

                return (addStatus == 0
                    ? (Result<string>)new Success<string>("&darkGray;Specified rights were successfully added")
                    : new Failure<string>("Unable to add user rights", addStatus));
            }
        }


        //--------------------------------------------------
        /// <summary>
        /// Gets rights of the specified user.
        /// </summary>
        [NotNull] private static Result<string> CommandGetRights([NotNull, ItemNotNull] string[] args)
        {
            // verify arguments
            if (args.Length != 2)
            {
                return new Failure<string>($"Expected exactly 1 parameter, username\n\n{Program.AllCommandsUsage}");
            }

            // verify that the specified account exists
            var sid = new byte[1024];
            var sidSize = sid.Length;
            var domainName = new StringBuilder(1024);
            var domainNameSize = domainName.Capacity;
            var accountType = 0;
            if (!NativeMethods.LookupAccountName(string.Empty, args[1], sid, ref sidSize, domainName, ref domainNameSize, ref accountType)) // inspired by "System.Environment.UserDomainName"
            {
                return new Failure<string>("Unknown account", Marshal.GetLastWin32Error());
            }

            // open LSA policy
            var objectAttributes = default(NativeMethods.LSA_OBJECT_ATTRIBUTES);
            var policyStatus = NativeMethods.LsaNtStatusToWinError(
                NativeMethods.LsaOpenPolicy(null, ref objectAttributes, NativeMethods.LSA_POLICY.POLICY_LOOKUP_NAMES, out var policyHandle));
            if (policyStatus != 0)
            {
                return new Failure<string>("Unable to open LSA policy", policyStatus);
            }

            // get user's rights
            using (policyHandle)
            {
                var enumStatus = NativeMethods.LsaNtStatusToWinError(
                    NativeMethods.LsaEnumerateAccountRights(policyHandle, sid, out var userRightsPtr, out var userRightsCount));
                if (enumStatus == 2) // status "0x00000002: The system cannot find the file specified" means "this user has no rights"
                {
                    return new Success<string>("<No rights>");
                }
                if (enumStatus != 0)
                {
                    return new Failure<string>("Unable to enumerate user rights", enumStatus);
                }
                using (userRightsPtr)
                {
                    var rights = new List<string>((int)userRightsCount);
                    var ptrOffset = Marshal.SizeOf(default(NativeMethods.LSA_UNICODE_STRING));
                    var ptr = userRightsPtr.DangerousGetHandle().ToInt64();
                    while (userRightsCount-- > 0)
                    {
                        var userRight = (NativeMethods.LSA_UNICODE_STRING)Marshal.PtrToStructure(new IntPtr(ptr), typeof(NativeMethods.LSA_UNICODE_STRING));
                        var userRightStr = Marshal.PtrToStringAuto(userRight.Buffer);
                        rights.Add(userRightStr.EscapeForColourOutput());
                        ptr += ptrOffset;
                    }
                    return new Success<string>(string.Join(Environment.NewLine, rights));
                }
            }
        }


        //--------------------------------------------------
        /// <summary>
        /// Gets current version of this application.
        /// </summary>
        [NotNull] private static Result<string> CommandGetVersion([NotNull, ItemNotNull] string[] args)
        {
            var codeBasePath = typeof(Program).Assembly.GetCodeBasePath(doNotThrow: true);

            return (codeBasePath == null
                ? (Result<string>)new Failure<string>("Unable to determine assembly location")
                : new Success<string>(FileVersionInfo.GetVersionInfo(codeBasePath).FileVersion));
        }


        //--------------------------------------------------
        /// <summary>
        /// Standard response when command specified on command
        /// line is not recognized.
        /// </summary>
        [NotNull] private static Result<string> CommandNotFound([NotNull, ItemNotNull] string[] args)
        {
            return new Failure<string>($"Unknown command \"{args[0]}\".\n\n{Program.AllCommandsUsage}");
        }


        //--------------------------------------------------
        /// <summary>
        /// Remove rights from the specified user.
        /// </summary>
        [NotNull] private static Result<string> CommandRemoveRights([NotNull, ItemNotNull] string[] args)
        {
            // verify arguments
            if (args.Length != 3)
            {
                return new Failure<string>($"Expected exactly 2 parameters, username and semicolonSeparatedRights\n\n{Program.AllCommandsUsage}");
            }

            // verify that the specified account exists
            var sid = new byte[1024];
            var sidSize = sid.Length;
            var domainName = new StringBuilder(1024);
            var domainNameSize = domainName.Capacity;
            var accountType = 0;
            if (!NativeMethods.LookupAccountName(string.Empty, args[1], sid, ref sidSize, domainName, ref domainNameSize, ref accountType)) // inspired by "System.Environment.UserDomainName"
            {
                return new Failure<string>("Unknown account", Marshal.GetLastWin32Error());
            }

            // open LSA policy
            var objectAttributes = default(NativeMethods.LSA_OBJECT_ATTRIBUTES);
            var policyStatus = NativeMethods.LsaNtStatusToWinError(
                NativeMethods.LsaOpenPolicy(null, ref objectAttributes, NativeMethods.LSA_POLICY.POLICY_LOOKUP_NAMES, out var policyHandle));
            if (policyStatus != 0)
            {
                return new Failure<string>("Unable to open LSA policy", policyStatus);
            }

            // set user's rights
            using (policyHandle)
            {
                var parsedRights = args[2]
                    .Split(';')
                    .Select(p => p.Trim())
                    .Where(p => !string.IsNullOrEmpty(p))
                    .ToArray();

                if (parsedRights.Length == 0)
                {
                    return new Failure<string>("No rights were specified");
                }

                var removeAll = parsedRights.Length == 1 && StringComparer.OrdinalIgnoreCase.Equals("--all", parsedRights[0]);
                var rights = (removeAll ? null : parsedRights
                    .Select(p => new NativeMethods.LSA_UNICODE_STRING
                    {
                        Buffer = Marshal.StringToHGlobalUni(p),
                        Length = (ushort)(p.Length * UnicodeEncoding.CharSize),
                        MaximumLength = (ushort)((p.Length + 1) * UnicodeEncoding.CharSize)
                    })
                    .ToArray());

                var removeStatus = NativeMethods.LsaNtStatusToWinError(
                    NativeMethods.LsaRemoveAccountRights(policyHandle, sid, removeAll, rights, rights == null ? 0 : (uint)rights.Length));

                // ReSharper disable once InvertIf - bad R# suggestion, makes code less readable
                if (rights != null)
                {
                    foreach (var right in rights) // release marshaled right strings
                    {
                        Marshal.FreeHGlobal(right.Buffer);
                    }
                }

                return (removeStatus == 0
                    ? (Result<string>)new Success<string>(removeAll
                        ? "&darkGray;All rights were successfully removed"
                        : "&darkGray;Specified rights were successfully removed")
                    : new Failure<string>("Unable to remove user rights", removeStatus));
            }
        }


        //--------------------------------------------------
        /// <summary>
        /// Standard usage response.
        /// </summary>
        [NotNull] private static Result<string> CommandUsage([NotNull, ItemNotNull] string[] args)
        {
            return new Success<string>(Program.AllCommandsUsage);
        }


        //--------------------------------------------------
        /// <summary>
        /// Gets full path of the of the given assembly
        /// (as specified originally, i.e. disregarding shadow copying).
        /// </summary>
        /// <remarks>
        /// From "Pandell.Common.AssemblyExtensions".
        /// </remarks>
        [ContractAnnotation("doNotThrow:false => notnull; doNotThrow:true => canbenull")]
        private static string GetCodeBasePath([CanBeNull] this Assembly assembly, bool doNotThrow = false)
        {
            if (assembly == null)
            {
                if (doNotThrow) { return null; }
                throw new ArgumentNullException(nameof(assembly));
            }

            const string localPathPrefix = "file:///";
            if (assembly.CodeBase.StartsWith(localPathPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return assembly.CodeBase.Substring(localPathPrefix.Length).Replace('/', Path.DirectorySeparatorChar);
            }

            const string uncPathPrefix = "file://";
            if (assembly.CodeBase.StartsWith(uncPathPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return assembly.CodeBase.Substring(uncPathPrefix.Length - 2).Replace('/', Path.DirectorySeparatorChar);
            }

            if (doNotThrow) { return null; }
            throw new ArgumentException("Specified assembly has unrecognized code-base location.", nameof(assembly));
        }


        //--------------------------------------------------
        /// <summary>
        /// P/Invoke definitions for LSA functions (AdvApi32.dll).
        /// </summary>
        [SuppressMessage("ReSharper", "InconsistentNaming", Justification = "Win32 API")]
        private static class NativeMethods
        {
            /// <summary>
            /// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721916(v=vs.85).aspx
            /// </summary>
            [Flags, PublicAPI]
            public enum LSA_POLICY
            {
                POLICY_VIEW_LOCAL_INFORMATION   = 0x0001,
                POLICY_VIEW_AUDIT_INFORMATION   = 0x0002,
                POLICY_GET_PRIVATE_INFORMATION  = 0x0004,
                POLICY_TRUST_ADMIN              = 0x0008,
                POLICY_CREATE_ACCOUNT           = 0x0010,
                POLICY_CREATE_SECRET            = 0x0020,
                POLICY_CREATE_PRIVILEGE         = 0x0040,
                POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x0080,
                POLICY_SET_AUDIT_REQUIREMENTS   = 0x0100,
                POLICY_AUDIT_LOG_ADMIN          = 0x0200,
                POLICY_SERVER_ADMIN             = 0x0400,
                POLICY_LOOKUP_NAMES             = 0x0800,
                POLICY_NOTIFICATION             = 0x1000
            }

            [StructLayout(LayoutKind.Sequential)]
            [UsedImplicitly(ImplicitUseTargetFlags.Members)]
            public struct LSA_OBJECT_ATTRIBUTES
            {
                public int Length;
                public IntPtr RootDirectory;
                public LSA_UNICODE_STRING ObjectName;
                public uint Attributes;
                public IntPtr SecurityDescriptor;
                public IntPtr SecurityQualityOfService;
            }

            [StructLayout(LayoutKind.Sequential)]
            [UsedImplicitly(ImplicitUseTargetFlags.Members)]
            [SuppressMessage("Microsoft.Design", "CA1049:Implement IDisposable on 'Program.NativeMethods.LSA_UNICODE_STRING'", Justification = "Win32 API")]
            public struct LSA_UNICODE_STRING
            {
                public ushort Length;
                public ushort MaximumLength;
                public IntPtr Buffer;
            }

            /// <summary>
            /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379159
            /// </summary>
            [DllImport("AdvApi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool LookupAccountName(
                string systemName,
                string accountName,
                byte[] accountSid,
                ref int accountSidSize,
                [Out] StringBuilder domainName,
                ref int domainNameSize,
                ref int accountSidUse);

            /// <summary>
            /// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721786
            /// </summary>
            [DllImport("AdvApi32.dll", CharSet = CharSet.Unicode)]
            public static extern uint LsaAddAccountRights(
                SafeLsaPolicyHandle policyHandle,
                byte[] accountSid,
                LSA_UNICODE_STRING[] rights,
                uint rightsCount);

            /// <summary>
            /// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721787
            /// </summary>
            [DllImport("AdvApi32.dll")]
            private static extern uint LsaClose(IntPtr handle);

            /// <summary>
            /// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721790
            /// </summary>
            [DllImport("AdvApi32.dll")]
            public static extern uint LsaEnumerateAccountRights(
                SafeLsaPolicyHandle policyHandle,
                byte[] accountSid,
                out SafeLsaBufferHandle rights,
                out uint rightsCount);

            /// <summary>
            /// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721796
            /// </summary>
            [DllImport("AdvApi32.dll")]
            private static extern uint LsaFreeMemory(IntPtr handle);

            /// <summary>
            /// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721800
            /// </summary>
            /// <remarks>
            /// Using "int" as return type for compatibility with
            /// .NET last-windows-error typing (even though Win32
            /// defines return value as ULONG which translates to uint:
            /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751#ULONG )
            /// </remarks>
            [DllImport("AdvApi32.dll")]
            public static extern int LsaNtStatusToWinError(uint status);

            /// <summary>
            /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa378299
            /// </summary>
            [DllImport("AdvApi32.dll", CharSet = CharSet.Unicode)]
            public static extern uint LsaOpenPolicy(
                string systemName,
                ref LSA_OBJECT_ATTRIBUTES objectAttributes,
                LSA_POLICY desiredAccess,
                out SafeLsaPolicyHandle policyHandle);

            /// <summary>
            /// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721786
            /// </summary>
            [DllImport("AdvApi32.dll", CharSet = CharSet.Unicode)]
            public static extern uint LsaRemoveAccountRights(
                SafeLsaPolicyHandle policyHandle,
                byte[] accountSid,
                bool allRights,
                LSA_UNICODE_STRING[] rights,
                uint rightsCount);

            /// <summary>
            /// Guard to automatically release LSA policy handle.
            /// </summary>
            /// <remarks>
            /// Based on <c>Microsoft.Win32.SafeHandles.SafeLsaPolicyHandle</c>
            /// which is <c>internal</c> so cannot be referenced by us.
            /// </remarks>
            /// <inheritdoc />
            [UsedImplicitly]
            public sealed class SafeLsaPolicyHandle : SafeHandleZeroOrMinusOneIsInvalid
            {
                public SafeLsaPolicyHandle() : base(ownsHandle: true) { }
                public SafeLsaPolicyHandle(IntPtr handle) : base(ownsHandle: true)
                {
                    this.SetHandle(handle);
                }

                protected override bool ReleaseHandle()
                {
                    return NativeMethods.LsaClose(this.handle) == 0;
                }
            }

            /// <summary>
            /// Guard to automatically release buffer allocated by LSA functions.
            /// </summary>
            /// <inheritdoc />
            [UsedImplicitly(ImplicitUseTargetFlags.Members)]
            public sealed class SafeLsaBufferHandle : SafeHandleZeroOrMinusOneIsInvalid
            {
                public SafeLsaBufferHandle() : base(ownsHandle: true) { }
                public SafeLsaBufferHandle(IntPtr handle) : base(ownsHandle: true)
                {
                    this.SetHandle(handle);
                }

                protected override bool ReleaseHandle()
                {
                    return NativeMethods.LsaFreeMemory(this.handle) == 0;
                }
            }
        }

    }

}
