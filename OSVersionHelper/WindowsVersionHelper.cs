﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using OSVersionHelper.Win32;
using Windows.Foundation.Metadata;
using Windows.Security.EnterpriseData;


#if NET5_0
using System.Runtime.Versioning;
[assembly: SupportedOSPlatform("windows")]
#endif

namespace OSVersionHelper
{
    public static class WindowsVersionHelper
    {
        private const string ContractName = "Windows.Foundation.UniversalApiContract";

        [SecurityCritical]
        static WindowsVersionHelper()
        {
            if (IsSince(WindowsVersions.Win10))
            {
                if (IsApiContractPresent(11))
                {
                    Windows10Release = Windows10Release.September2020;
                } else if (IsApiContractPresent(10))
                {
                    Windows10Release = Windows10Release.May2020;
                }
                else if (IsApiContractPresent(9))
                {
                    Windows10Release = Windows10Release.November2019;
                }
                else if (IsApiContractPresent(8))
                {
                    Windows10Release = Windows10Release.May2019;
                }
                else if (IsApiContractPresent(7))
                {
                    Windows10Release = Windows10Release.October2018;
                }
                else if (IsApiContractPresent(6))
                {
                    Windows10Release = Windows10Release.April2018;
                }
                else if (IsApiContractPresent(5))
                {
                    Windows10Release = Windows10Release.FallCreators;
                }
                else if (IsApiContractPresent(4))
                {
                    Windows10Release = Windows10Release.Creators;
                }
                else if (IsApiContractPresent(3))
                {
                    Windows10Release = Windows10Release.Anniversary;
                }
                else if (IsApiContractPresent(2))
                {
                    Windows10Release = Windows10Release.Threshold2;
                }
                else if (IsApiContractPresent(1))
                {
                    Windows10Release = Windows10Release.Threshold1;
                }
                else
                {
                    Windows10Release = Windows10Release.Unknown;
                }
            }
        }

        public static bool IsWindowsNt { get; } = Environment.OSVersion.Platform == PlatformID.Win32NT;

        public static bool EdgeExists { get; } = File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), ExternDll.EdgeHtml));

        public static bool IsWindows10 { get; } = IsWindowsNt && IsSince(WindowsVersions.Win10);


        /// <summary>
        /// Gets a value indicating whether the current OS is Windows 10 September 2020 Update (20H02) or greater
        /// </summary>
        public static bool IsWindows10September2020OrGreater => IsWindows10 && Windows10Release >= Windows10Release.September2020;

        /// <summary>
        /// Gets a value indicating whether the current OS is Windows 10 May 2020 Update (20H01) or greater
        /// </summary>
        public static bool IsWindows10May2020OrGreater => IsWindows10 && Windows10Release >= Windows10Release.May2020;

        /// <summary>
        /// Gets a value indicating whether the current OS is Windows 10 November 2019 Update (19H02) or greater
        /// </summary>
        public static bool IsWindows10November2019OrGreater => IsWindows10 && Windows10Release >= Windows10Release.November2019;

        /// <summary>
        /// Gets a value indicating whether the current OS is Windows 10 May 2019 Update (19H01) or greater
        /// </summary>
        public static bool IsWindows10May2019OrGreater => IsWindows10 && Windows10Release >= Windows10Release.May2019;

        /// <summary>
        /// Gets a value indicating whether the current OS is Windows 10 October 2018 Update (Redstone 5) or greater
        /// </summary>
        public static bool IsWindows10October2018OrGreater => IsWindows10 && Windows10Release >= Windows10Release.October2018;

        /// <summary>
        /// Gets a value indicating whether the current OS is Windows 10 April 2018 Update (Redstone 4) or greater
        /// </summary>
        public static bool IsWindows10April2018OrGreater => IsWindows10 && Windows10Release >= Windows10Release.April2018;

        /// <summary>
        /// Gets a value indicating whether the current OS is Windows 10 Fall Creators Update (Redstone 3) or greater
        /// </summary>
        public static bool IsWindows10FallCreatorsOrGreater => IsWindows10 && Windows10Release >= Windows10Release.FallCreators;

        /// <summary>
        /// Gets a value indicating whether the current OS is Windows 10 Creators Update (Redstone 2) or greater
        /// </summary>
        public static bool IsWindows10CreatorsOrGreater => IsWindows10 && Windows10Release >= Windows10Release.Creators;

        /// <summary>
        /// Gets a value indicating whether the current OS is Windows 10 Anniversary Update (Redstone 1) or greater
        /// </summary>
        public static bool IsWindows10AnniversaryOrGreater => IsWindows10 && Windows10Release >= Windows10Release.Anniversary;

        /// <summary>
        /// Gets a value indicating whether the current OS is Windows 10 Threshold 2 or greater
        /// </summary>
        public static bool IsWindows10Threshold2OrGreater => IsWindows10 && Windows10Release >= Windows10Release.Threshold2;

        /// <summary>
        /// Gets a value indicating whether the current OS is Windows 10 Threshold 1 or greater
        /// </summary>
        public static bool IsWindows10Threshold1OrGreater => IsWindows10 && Windows10Release >= Windows10Release.Threshold1;

        public static bool IsWorkstation { get; } = !IsServer();

        public static bool UseWindowsInformationProtectionApi
        {
            [SecurityCritical]
            get => Windows10Release >= Windows10Release.Anniversary && ProtectionPolicyManagerEnabled();
        }

        public static Windows10Release Windows10Release { get; }
        
        /// <summary>
        /// True if the app has a package identity and can call API's that require one
        /// </summary>
        public static bool HasPackageIdentity { get; } = GetPackageFamilyName() != null;

        [SecurityCritical]
        // Don't load types from here accidently
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static bool IsApiContractPresent(ushort majorVersion) => ApiInformation.IsApiContractPresent(ContractName, majorVersion);

        [SecurityCritical]
        private static bool IsServer()
        {
            var versionInfo = NativeMethods.RtlGetVersion();
            return versionInfo.ProductType == ProductType.VER_NT_DOMAIN_CONTROLLER
                   || versionInfo.ProductType == ProductType.VER_NT_SERVER;
        }

        [SecurityCritical]
        public static bool IsSince(WindowsVersions version)
        {
            int major;
            int minor;

            switch (version)
            {
                case WindowsVersions.Win7:
                case WindowsVersions.Server2008R2:
                    major = 6;
                    minor = 1;
                    break;

                case WindowsVersions.Win8:
                case WindowsVersions.Server2012:
                    major = 6;
                    minor = 2;
                    break;

                case WindowsVersions.Win81:
                case WindowsVersions.Server2012R2:
                    major = 6;
                    minor = 3;
                    break;

                case WindowsVersions.Win10:
                case WindowsVersions.Server2016:
                case WindowsVersions.Server2019:
                    major = 10;
                    minor = 0;
                    break;

                default:
                    throw new ArgumentException("Unrecognized Operating System", nameof(version));
            }

            // After 8.1 apps without manifest or are not manifested for 8.1/10 return 6.2 when using GetVersionEx.
            // Need to use RtlGetVersion to get correct major/minor/build
            var os = NativeMethods.RtlGetVersion();

            if (os.MajorVersion > major)
            {
                return true;
            }

            if (os.MajorVersion == major)
            {
                return os.MinorVersion >= minor;
            }

            return false;
        }
  
        // Don't load types from here accidently
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static bool ProtectionPolicyManagerEnabled() => ProtectionPolicyManager.IsProtectionEnabled;


        [DllImport(ExternDll.Kernel32, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetCurrentPackageFullName(ref int packageFullNameLength, StringBuilder packageFullName);

        /// <summary>
        /// Gets the package family name if the process has an identity
        /// </summary>
        /// <returns>The package family name or null if the process isn't running with an identity</returns>
        public static string GetPackageFamilyName()
        {
            if(IsSince(WindowsVersions.Win8))
            {
                var length = 0;
                var sb = new StringBuilder(0);
                var result = GetCurrentPackageFullName(ref length, sb);

                sb = new StringBuilder(length);
                result = GetCurrentPackageFullName(ref length, sb);
                
                if(result != APPMODEL_ERROR_NO_PACKAGE)
                {
                    return sb.ToString();
                }
            }
            return null;
        }

        const long APPMODEL_ERROR_NO_PACKAGE = 15700L;

    }
}
