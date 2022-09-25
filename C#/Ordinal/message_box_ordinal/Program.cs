using System;
using System.Runtime.InteropServices;

namespace Ordinals
{
    internal class Program
    { //WE USE PEVIEW -> SECTION .TEXT -> EXPORT ADDRESS TABLE -> MESSAGEBOXW TO FIND ORDINAL 0X0874 -> 2164
        [DllImport("user32.dll", EntryPoint = "#2164", CharSet = CharSet.Unicode)]
        static extern int NotAMessageBox(IntPtr hWnd, string lpText, string lpCaption, uint uType);

        static void Main(string[] args)
        {
            NotAMessageBox(IntPtr.Zero, "Ordinal!!", "Ordinal", 0);
        }

    }


}