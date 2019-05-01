| Title                | Suspicious Control Panel DLL Load                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li><li>[T1085: Rundll32](../Triggers/T1085.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/rikvduijn/status/853251879320662017](https://twitter.com/rikvduijn/status/853251879320662017)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious Control Panel DLL Load
status: experimental
description: Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits
author: Florian Roth
date: 2017/04/15
references:
    - https://twitter.com/rikvduijn/status/853251879320662017
tags:
    - attack.defense_evasion
    - attack.t1073
    - attack.t1085
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\System32\control.exe'
        CommandLine: '*\rundll32.exe *'
    filter:
        CommandLine: '*Shell32.dll*'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
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
((ParentImage:"*\\\\System32\\\\control.exe" AND CommandLine:"*\\\\rundll32.exe *") AND NOT (CommandLine:"*Shell32.dll*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\\System32\\control\\.exe)(?=.*.*\\rundll32\\.exe .*)))(?=.*(?!.*(?:.*(?=.*.*Shell32\\.dll.*)))))'
```



