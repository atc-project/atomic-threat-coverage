| Title                | Logon Scripts (UserInitMprLogonScript)                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects creation or execution of UserInitMprLogonScript persistence method                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1037: Logon Scripts](https://attack.mitre.org/techniques/T1037)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li><li>[DN_0018_14_windows_sysmon_RegistryEvent](../Data_Needed/DN_0018_14_windows_sysmon_RegistryEvent.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1037: Logon Scripts](../Triggers/T1037.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>exclude legitimate logon scripts</li><li>penetration tests, red teaming</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)</li></ul>                                                          |
| Author               | Tom Ueltschi (@c_APT_ure)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Logon Scripts (UserInitMprLogonScript)
status: experimental
description: Detects creation or execution of UserInitMprLogonScript persistence method
references:
    - https://attack.mitre.org/techniques/T1037/
tags:
    - attack.t1037
    - attack.persistence
    - attack.lateral_movement
author: Tom Ueltschi (@c_APT_ure)
logsource:
    product: windows
    service: sysmon
detection:
    exec_selection:
        EventID: 1 # Migration to process_creation requires multipart YAML
        ParentImage: '*\userinit.exe'
    exec_exclusion:
        Image: '*\explorer.exe'
        CommandLine: '*\netlogon.bat'
    create_selection:
        EventID:
            - 1
            - 11
            - 12
            - 13
            - 14
    create_keywords:
        - UserInitMprLogonScript
    condition: (exec_selection and not exec_exclusion) or (create_selection and create_keywords)
falsepositives:
    - exclude legitimate logon scripts
    - penetration tests, red teaming
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
(((EventID:"1" AND ParentImage:"*\\\\userinit.exe") AND NOT (Image:"*\\\\explorer.exe" AND CommandLine:"*\\\\netlogon.bat")) OR (EventID:("1" "11" "12" "13" "14") AND "UserInitMprLogonScript"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*(?=.*1)(?=.*.*\\userinit\\.exe)))(?=.*(?!.*(?:.*(?=.*.*\\explorer\\.exe)(?=.*.*\\netlogon\\.bat)))))|.*(?:.*(?=.*(?:.*1|.*11|.*12|.*13|.*14))(?=.*UserInitMprLogonScript))))'
```



