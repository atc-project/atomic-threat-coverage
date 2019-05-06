| Title                | UAC Bypass via Event Viewer                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects UAC bypass method using Windows event viewer                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1088: Bypass User Account Control](../Triggers/T1088.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)</li><li>[https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100](https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: UAC Bypass via Event Viewer
status: experimental
description: Detects UAC bypass method using Windows event viewer
references:
    - https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
    - https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100
author: Florian Roth
logsource:
    product: windows
    service: sysmon
detection:
    methregistry:
        EventID: 13
        TargetObject: 'HKEY_USERS\\*\mscfile\shell\open\command'
    methprocess:
        EventID: 1 # Migration to process_creation requires multipart YAML
        ParentImage: '*\eventvwr.exe'
    filterprocess:
        Image: '*\mmc.exe'
    condition: methregistry or ( methprocess and not filterprocess )
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1088
falsepositives:
    - unknown
level: critical
```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
((EventID:"13" AND TargetObject:"HKEY_USERS\\\\*\\\\mscfile\\\\shell\\\\open\\\\command") OR ((EventID:"1" AND ParentImage:"*\\\\eventvwr.exe") AND NOT (Image:"*\\\\mmc.exe")))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*13)(?=.*HKEY_USERS\\\\.*\\mscfile\\shell\\open\\command))|.*(?:.*(?=.*(?:.*(?=.*1)(?=.*.*\\eventvwr\\.exe)))(?=.*(?!.*(?:.*(?=.*.*\\mmc\\.exe)))))))'
```



