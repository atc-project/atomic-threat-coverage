| Title                | Shells Spawned by Web Servers                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Particular web applications may spawn a shell process legitimately</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Thomas Patzke                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Shells Spawned by Web Servers
status: experimental
description: Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack
author: Thomas Patzke
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\w3wp.exe'
            - '*\httpd.exe'
            - '*\nginx.exe'
            - '*\php-cgi.exe'
        Image:
            - '*\cmd.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\powershell.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1100
falsepositives:
    - Particular web applications may spawn a shell process legitimately
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
(ParentImage:("*\\\\w3wp.exe" "*\\\\httpd.exe" "*\\\\nginx.exe" "*\\\\php\\-cgi.exe") AND Image:("*\\\\cmd.exe" "*\\\\sh.exe" "*\\\\bash.exe" "*\\\\powershell.exe"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\w3wp\\.exe|.*.*\\httpd\\.exe|.*.*\\nginx\\.exe|.*.*\\php-cgi\\.exe))(?=.*(?:.*.*\\cmd\\.exe|.*.*\\sh\\.exe|.*.*\\bash\\.exe|.*.*\\powershell\\.exe)))'
```



