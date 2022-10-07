using System;
using System.Runtime.InteropServices;

using DInvoke.DynamicInvoke;

namespace ConsoleApp1
{
    internal class Program
    {
        public static class Win32
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct STARTUPINFO
            {
                public int cb;
                public IntPtr lpReserved;
                public IntPtr lpDesktop;
                public IntPtr lpTitle;
                public int dwX;
                public int dwY;
                public int dwXSize;
                public int dwYSize;
                public int dwXCountChars;
                public int dwYCountChars;
                public int dwFillAttribute;
                public int dwFlags;
                public short wShowWindow;
                public short cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public int dwProcessId;
                public int dwThreadId;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_ATTRIBUTES
            {
                public int nLength;
                public IntPtr lpSecurityDescriptor;
                public bool bInheritHandle;
            }

            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
            public delegate bool CreateProcessW(
                string lpApplicationName,
                string lpCommandLine,
                ref SECURITY_ATTRIBUTES lpProcessAttributes,
                ref SECURITY_ATTRIBUTES lpThreadAttributes,
                bool bInheritHandles,
                uint dwCreationFlags,
                IntPtr lpEnvironment,
                string lpCurrentDirectory,
                ref STARTUPINFO lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);
        }

        static void Main(string[] args)
        {
            var si = new Win32.STARTUPINFO();
            si.cb = Marshal.SizeOf(si);

            var pa = new Win32.SECURITY_ATTRIBUTES();
            pa.nLength = Marshal.SizeOf(pa);

            var ta = new Win32.SECURITY_ATTRIBUTES();
            ta.nLength = Marshal.SizeOf(ta);

            var pi = new Win32.PROCESS_INFORMATION();

            object[] parameters =
            {
                "C:\\Windows\\System32\\notepad.exe", null, pa, ta, false, (uint)0, IntPtr.Zero,
                "C:\\Windows\\System32", si, pi
            };

            var success = (bool)Generic.DynamicAPIInvoke("kernel32.dll", "CreateProcessW",
                typeof(Win32.CreateProcessW), ref parameters);

            if (success)
            {
                pi = (Win32.PROCESS_INFORMATION)parameters[9];
                Console.WriteLine("Process created with PID: {0}", pi.dwProcessId);
            }
            else
            {
                Console.WriteLine("Failed to create process. Error code: {0}.", Marshal.GetLastWin32Error());
            }
        }
    }
}