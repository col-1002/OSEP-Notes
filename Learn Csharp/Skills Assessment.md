## Scenario
You are part of a team of software developers building a tool to enhance network security. This tool should be able to scan a target host and find sensitive files that should not exist on the server; in this case, you are specifically looking for a `flag.txt` file. To make this operation more efficient, you have been provided with a wordlist in the `Assessment.dll` library, which includes common paths in which sensitive files are known to exist. The word list is accessible in the `GetWordList()` method in the `Words` class, via the `Assessment` namespace.

Your task is to create a C# application that will iterate through the wordlist, using each word as a potential path on the target host. You will make HTTP requests to these paths and check for the existence of `flag.txt`. The program will output the paths where the `flag.txt` file exists.

*What is the content of the `flag.txt` file found in the subdirectory you scanned for?*
## Solution


Step 1. I downloaded and unzip the file "Assessment.zip" 
Step 2. I created a new Console Application - I'm using Visual Studio.

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

Step 3. I add a reference to the assessment library - the assessment DLL file.

![[Screenshot 2024-05-26 195803.png]]

We will use the code from the `asynchronous programming` section, tweaking it a bit.

Step 4. I use the `GetWordList` method from the `Words` class in order to access the word list.

```csharp
Words assessmentWords = new Words();
var wordList = assessmentWords.GetWordList();
```

`CancellationToken` is a struct that can be checked periodically by an operation, and if cancellation is requested, the operation can stop itself in a controlled manner.

```csharp
await Parallel.ForEachAsync(wordList, async (word, cancellationToken) =>
{
// send Request to server and get the Response body if finb the flag.txt
});
```

The `GetWebsiteContentAsync` method fetches the content of the given URL using the `HttpClient` class and returns the `HttpResponseMessage` containing the server's response.

```csharp
    static async Task<HttpResponseMessage> GetWebsiteContentAsync(string url)
    {
        HttpResponseMessage response = await client.GetAsync(url); // Send a GET request
        return response;
    }
}
```

Step 5. Parallel.ForEachAsync Method
- https://stackoverflow.com/questions/70249422/using-parallel-foreachasync
- https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.parallel.foreachasync?view=net-8.0

#### The final script

```csharp
using System;
using System.Net.Http;
using Assessment;
using System.Threading.Tasks;
using System.Collections.Generic;

class Program
{
    private static readonly HttpClient client = new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(20)  // Timeout after 20 seconds
    };

    static async Task Main(string[] args)
    {
        Words assessmentWords = new Words();
        var wordList = assessmentWords.GetWordList(); // Get wordlists from the DLL libs

        Console.Write("Please enter URI (e.g., http://10.10.x.x): "); // Take the input
        string baseUrl = Console.ReadLine();

        if (baseUrl.EndsWith("/"))
        {
            baseUrl += "/"; // Ensure the URL ends with a slash for proper URI concatenation
        }

        await Parallel.ForEachAsync(wordList, async (word, cancellationToken) =>
        {
            string url = $"{baseUrl}{word}/flag.txt";
            try
            {
                HttpResponseMessage response = await GetWebsiteContentAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    string responseBody = await response.Content.ReadAsStringAsync(); // Read the response content
                    Console.WriteLine($"Found flag.txt in the {word} directory, content:"); // Output the flag.txt
                    Console.WriteLine(responseBody);
                }
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"Error fetching {url}: {ex.Message}");
            }
        });
    }

    static async Task<HttpResponseMessage> GetWebsiteContentAsync(string url)
    {
        HttpResponseMessage response = await client.GetAsync(url); // Send a GET request
        return response;
    }
}
```

Running the program, I found the flag exists in the `htbhacks` directory, and the contents of flag.txt:

![[Pasted image 20240526231503.png]]

HTB{CSh4rp_Pr0gr4mm1ng}
.