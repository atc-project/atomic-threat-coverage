| Title            | LP_0110_windows_powershell_transcript                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Records each PowerShell session with input and output to a file                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | High                                                                    |
| **EventID**      | <ul><li>None</li></ul>         |
| **References**   | <ul><li>[https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html)</li></ul> |



## Configuration

Manual steps to implement logging policy:

```
Computer Configuration > 
Administrative Templates > 
Windows PowerShell > 
Turn on PowerShell Script Block Transcription (Enable)
Check "Include Invokation headers"
Put Path to Output Directory (if not set it will be stored under user's documents)
```

Enabling via registry key:
```
reg add "hklm\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1
reg add "hklm\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1
reg add "hklm\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\pstranscripts"
```


