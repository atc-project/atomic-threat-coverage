| Title                | Powershell AMSI Bypass via .NET Reflection                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Request to amsiInitFailed that can be used to disable AMSI Scanning                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/mattifestation/status/735261176745988096](https://twitter.com/mattifestation/status/735261176745988096)</li><li>[https://www.hybrid-analysis.com/sample/0ced17419e01663a0cd836c9c2eb925e3031ffb5b18ccf35f4dea5d586d0203e?environmentId=120](https://www.hybrid-analysis.com/sample/0ced17419e01663a0cd836c9c2eb925e3031ffb5b18ccf35f4dea5d586d0203e?environmentId=120)</li></ul>                                                          |
| Author               | Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Powershell AMSI Bypass via .NET Reflection
status: experimental
description: Detects Request to amsiInitFailed that can be used to disable AMSI Scanning
references:
    - https://twitter.com/mattifestation/status/735261176745988096
    - https://www.hybrid-analysis.com/sample/0ced17419e01663a0cd836c9c2eb925e3031ffb5b18ccf35f4dea5d586d0203e?environmentId=120
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1086
author: Markus Neis
date: 2018/08/17
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '*System.Management.Automation.AmsiUtils*'
    selection2:
        CommandLine:
            - '*amsiInitFailed*'
    condition: selection1 and selection2
    falsepositives:
        - Potential Admin Activity
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
(CommandLine:("*System.Management.Automation.AmsiUtils*") AND CommandLine:("*amsiInitFailed*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*System\\.Management\\.Automation\\.AmsiUtils.*))(?=.*(?:.*.*amsiInitFailed.*)))'
```



