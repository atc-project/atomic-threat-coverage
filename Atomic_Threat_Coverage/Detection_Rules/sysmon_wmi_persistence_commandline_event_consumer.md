| Title                | WMI Persistence - Command Line Event Consumer                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects WMI command line event consumers                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1084)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](../Triggers/T1084.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown (data set is too small; further testing needed)</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)</li></ul>                                                          |
| Author               | Thomas Patzke                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: WMI Persistence - Command Line Event Consumer
status: experimental
description: Detects WMI command line event consumers
references:
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
author: Thomas Patzke
date: 2018/03/07
tags:
    - attack.t1084
    - attack.persistence
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7
        Image: 'C:\Windows\System32\wbem\WmiPrvSE.exe'
        ImageLoaded: 'wbemcons.dll'
    condition: selection
falsepositives: 
    - Unknown (data set is too small; further testing needed)
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
(EventID:"7" AND Image:"C\\:\\\\Windows\\\\System32\\\\wbem\\\\WmiPrvSE.exe" AND ImageLoaded:"wbemcons.dll")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*7)(?=.*C:\\Windows\\System32\\wbem\\WmiPrvSE\\.exe)(?=.*wbemcons\\.dll))'
```



