using System;
using System.Runtime.InteropServices;

namespace PInvoke
{
    internal class Program
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern int MessageBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType);

        static void Main(string[] args)
        {
            MessageBoxW(IntPtr.Zero, "My first P/Invoke", "Hello World!", 0);
        }

    }


}