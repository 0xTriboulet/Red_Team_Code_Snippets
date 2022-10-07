using System;
using System.Runtime.InteropServices;

using DInvoke.DynamicInvoke;

namespace MessageBoxW_DInvoke
{
    class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate int MessageBoxW(IntPtr hWnd, string lpText, string pCaption, uint uType);
        static void Main(string[] args)
        {
            var parameters = new object[] { IntPtr.Zero, "My first D/Invoke!", "Hello world!", (uint)0 };
            Generic.DynamicAPIInvoke("user32.dll", "MessageBoxW", typeof(MessageBoxW), ref parameters);

        }
    }
}
