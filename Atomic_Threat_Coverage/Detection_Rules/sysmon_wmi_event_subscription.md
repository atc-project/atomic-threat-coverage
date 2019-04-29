| Title                | WMI Event Subscription                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects creation of WMI event subscription persistence method                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1084)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0023_20_windows_sysmon_WmiEvent](../Data_Needed/DN_0023_20_windows_sysmon_WmiEvent.md)</li><li>[DN_0024_21_windows_sysmon_WmiEvent](../Data_Needed/DN_0024_21_windows_sysmon_WmiEvent.md)</li><li>[DN_0022_19_windows_sysmon_WmiEvent](../Data_Needed/DN_0022_19_windows_sysmon_WmiEvent.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](../Triggers/T1084.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>exclude legitimate (vetted) use of WMI event subscription in your network</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://attack.mitre.org/techniques/T1084/](https://attack.mitre.org/techniques/T1084/)</li></ul>                                                          |
| Author               | Tom Ueltschi (@c_APT_ure)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: WMI Event Subscription
status: experimental
description: Detects creation of WMI event subscription persistence method
references:
    - https://attack.mitre.org/techniques/T1084/
tags:
    - attack.t1084
    - attack.persistence
author: Tom Ueltschi (@c_APT_ure)
date: 2019/01/12
logsource:
    product: windows
    service: sysmon
detection:
    selector:
        EventID:
            - 19
            - 20
            - 21
    condition: selector
falsepositives:
    - exclude legitimate (vetted) use of WMI event subscription in your network
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
EventID:("19" "20" "21")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*19|.*20|.*21)'
```



