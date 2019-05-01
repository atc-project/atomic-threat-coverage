| Title                | Bitsadmin Download                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects usage of bitsadmin downloading a file                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1197: BITS Jobs](https://attack.mitre.org/techniques/T1197)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1197: BITS Jobs](../Triggers/T1197.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Some legitimate apps use this, but limited.</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin](https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin)</li><li>[https://isc.sans.edu/diary/22264](https://isc.sans.edu/diary/22264)</li></ul>                                                          |
| Author               | Michael Haag                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0190</li><li>attack.s0190</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Bitsadmin Download
status: experimental
description: Detects usage of bitsadmin downloading a file
references:
        - https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
        - https://isc.sans.edu/diary/22264
tags:
        - attack.defense_evasion
        - attack.persistence
        - attack.t1197
        - attack.s0190
author: Michael Haag
logsource:
        category: process_creation
        product: windows
detection:
        selection:
                Image:
                        - '*\bitsadmin.exe'
                CommandLine:
                        - '/transfer'
        condition: selection
fields:
        - CommandLine
        - ParentCommandLine
falsepositives:
        - Some legitimate apps use this, but limited.
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
(Image:("*\\\\bitsadmin.exe") AND CommandLine:("\\/transfer"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\bitsadmin\\.exe))(?=.*(?:.*/transfer)))'
```



