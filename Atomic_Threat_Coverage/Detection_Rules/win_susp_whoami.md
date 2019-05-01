| Title                | Whoami Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1033: System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1033: System Owner/User Discovery](../Triggers/T1033.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Admin activity</li><li>Scripts and administrative tools used in the monitored environment</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/haroonmeer/status/939099379834658817](https://twitter.com/haroonmeer/status/939099379834658817)</li><li>[https://twitter.com/c_APT_ure/status/939475433711722497](https://twitter.com/c_APT_ure/status/939475433711722497)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Whoami Execution
status: experimental
description: Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators
references:
    - https://twitter.com/haroonmeer/status/939099379834658817
    - https://twitter.com/c_APT_ure/status/939475433711722497
author: Florian Roth
date: 2018/05/22
tags:
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: whoami
    condition: selection
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment
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
CommandLine:"whoami"
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^whoami'
```



