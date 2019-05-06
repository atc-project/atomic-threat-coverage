| Title                | DNS ServerLevelPluginDll Install                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required)                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
---
action: global
title: DNS ServerLevelPluginDll Install
status: experimental
description: Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server (restart required)
references:
    - https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
date: 2017/05/08
author: Florian Roth
tags:
    - attack.defense_evasion
    - attack.t1073
detection:
    condition: 1 of them
fields:
    - EventID
    - CommandLine
    - ParentCommandLine
    - Image
    - User
    - TargetObject
falsepositives:
    - unknown
level: high
---
logsource:
    product: windows
    service: sysmon
detection:
    dnsregmod:
        EventID: 13
        TargetObject: '*\services\DNS\Parameters\ServerLevelPluginDll'
---
logsource:
    category: process_creation
    product: windows
detection:
    dnsadmin:
        CommandLine: 'dnscmd.exe /config /serverlevelplugindll *'
```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(EventID:"13" AND TargetObject:"*\\\\services\\\\DNS\\\\Parameters\\\\ServerLevelPluginDll")\nCommandLine:"dnscmd.exe \\/config \\/serverlevelplugindll *"
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*.*\\services\\DNS\\Parameters\\ServerLevelPluginDll))'\ngrep -P '^dnscmd\\.exe /config /serverlevelplugindll .*'
```



