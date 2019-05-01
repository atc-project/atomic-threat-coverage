| Title                | Malicious Service Installations                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1050: New Service](../Triggers/T1050.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Penetration testing</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Malicious Service Installations
description: Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity
author: Florian Roth
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1050
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    malsvc_wce:
        ServiceName: 
            - 'WCESERVICE'
            - 'WCE SERVICE'
    malsvc_paexec:
        ServiceFileName: '*\PAExec*'
    malsvc_winexe:
        ServiceFileName: 'winexesvc.exe*'
    malsvc_pwdumpx:
        ServiceFileName: '*\DumpSvc.exe'
    malsvc_wannacry:
        ServiceName: 'mssecsvc2.0'
    malsvc_persistence:
        ServiceFileName: '* net user *'
    malsvc_others:
        ServiceName:
            - 'pwdump*'
            - 'gsecdump*'
            - 'cachedump*'
    condition: selection and 1 of malsvc_*
falsepositives: 
    - Penetration testing
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
(EventID:"7045" AND (ServiceName:("WCESERVICE" "WCE SERVICE") OR ServiceFileName:"*\\\\PAExec*" OR ServiceFileName:"winexesvc.exe*" OR ServiceFileName:"*\\\\DumpSvc.exe" OR ServiceName:"mssecsvc2.0" OR ServiceFileName:"* net user *" OR ServiceName:("pwdump*" "gsecdump*" "cachedump*")))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*(?:.*(?:.*(?:.*WCESERVICE|.*WCE SERVICE)|.*.*\\PAExec.*|.*winexesvc\\.exe.*|.*.*\\DumpSvc\\.exe|.*mssecsvc2\\.0|.*.* net user .*|.*(?:.*pwdump.*|.*gsecdump.*|.*cachedump.*)))))'
```



