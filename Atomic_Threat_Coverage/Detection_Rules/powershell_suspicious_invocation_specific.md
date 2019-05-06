| Title                | Suspicious PowerShell Invocations - Specific                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious PowerShell invocation command parameters                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Penetration tests</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth (rule)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Invocations - Specific
status: experimental
description: Detects suspicious PowerShell invocation command parameters
tags:
    - attack.execution
    - attack.t1086
author: Florian Roth (rule)
logsource:
    product: windows
    service: powershell
detection:
    keywords:
        - ' -nop -w hidden -c * [Convert]::FromBase64String'
        - ' -w hidden -noni -nop -c "iex(New-Object'
        - ' -w hidden -ep bypass -Enc'
        - 'powershell.exe reg add HKCU\software\microsoft\windows\currentversion\run'
        - 'bypass -noprofile -windowstyle hidden (new-object system.net.webclient).download'
        - 'iex(New-Object Net.WebClient).Download'
    condition: keywords
falsepositives:
    - Penetration tests
level: high

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(" \\-nop \\-w hidden \\-c * \\[Convert\\]\\:\\:FromBase64String" OR " \\-w hidden \\-noni \\-nop \\-c \\"iex\\(New\\-Object" OR " \\-w hidden \\-ep bypass \\-Enc" OR "powershell.exe reg add HKCU\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run" OR "bypass \\-noprofile \\-windowstyle hidden \\(new\\-object system.net.webclient\\).download" OR "iex\\(New\\-Object Net.WebClient\\).Download")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P \'^(?:.*(?:.* -nop -w hidden -c .* \\[Convert\\]::FromBase64String|.* -w hidden -noni -nop -c "iex\\(New-Object|.* -w hidden -ep bypass -Enc|.*powershell\\.exe reg add HKCU\\software\\microsoft\\windows\\currentversion\\run|.*bypass -noprofile -windowstyle hidden \\(new-object system\\.net\\.webclient\\)\\.download|.*iex\\(New-Object Net\\.WebClient\\)\\.Download))\'
```



