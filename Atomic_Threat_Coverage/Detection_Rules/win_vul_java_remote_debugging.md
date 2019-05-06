| Title                | Java Running with Remote Debugging                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a JAVA process running with remote debugging allowing more than just localhost to connect                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1046: Network Service Scanning](https://attack.mitre.org/techniques/T1046)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1046: Network Service Scanning](../Triggers/T1046.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Java Running with Remote Debugging
description: Detects a JAVA process running with remote debugging allowing more than just localhost to connect
author: Florian Roth
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*transport=dt_socket,address=*'
    exclusion:
        - CommandLine: '*address=127.0.0.1*'
        - CommandLine: '*address=localhost*'
    condition: selection and not exclusion
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: medium

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(CommandLine:"*transport=dt_socket,address=*" AND NOT (CommandLine:"*address=127.0.0.1*" OR CommandLine:"*address=localhost*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*.*transport=dt_socket,address=.*)(?=.*(?!.*(?:.*(?:.*(?=.*.*address=127\\.0\\.0\\.1.*)|.*(?=.*.*address=localhost.*))))))'
```



