| Title                | UAC Bypass via sdclt                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects changes to HKCU:\Software\Classes\exefile\shell\runas\command\isolatedCommand                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1088: Bypass User Account Control](../Triggers/T1088.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)</li></ul>                                                          |
| Author               | Omer Yampel                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: UAC Bypass via sdclt
status: experimental
description: Detects changes to HKCU:\Software\Classes\exefile\shell\runas\command\isolatedCommand
references:
    - https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/
author: Omer Yampel
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13 
        TargetObject: 'HKEY_USERS\\*\Classes\exefile\shell\runas\command\isolatedCommand'
    condition: selection
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1088
falsepositives:
    - unknown
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
(EventID:"13" AND TargetObject:"HKEY_USERS\\\\*\\\\Classes\\\\exefile\\\\shell\\\\runas\\\\command\\\\isolatedCommand")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*HKEY_USERS\\\\.*\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand))'
```



