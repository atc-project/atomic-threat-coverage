| Title                | Malicious Service Installations                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li></ul>  |
| Data Needed          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1050: New Service](../Triggers/T1050.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Penetration testing</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-09-005</li><li>car.2013-09-005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Malicious Service Installations
id: 5a105d34-05fc-401e-8553-272b45c1522d
description: Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity
author: Florian Roth
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1050
    - car.2013-09-005
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





### splunk
    
```
(EventID="7045" ((ServiceName="WCESERVICE" OR ServiceName="WCE SERVICE") OR ServiceFileName="*\\\\PAExec*" OR ServiceFileName="winexesvc.exe*" OR ServiceFileName="*\\\\DumpSvc.exe" OR ServiceName="mssecsvc2.0" OR ServiceFileName="* net user *" OR (ServiceName="pwdump*" OR ServiceName="gsecdump*" OR ServiceName="cachedump*")))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Malicious Service Installations]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Malicious Service Installations status:  \
description: Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity \
references:  \
tags: ['attack.persistence', 'attack.privilege_escalation', 'attack.t1050', 'car.2013-09-005'] \
author: Florian Roth \
date:  \
falsepositives: ['Penetration testing'] \
level: critical
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="7045" ((ServiceName="WCESERVICE" OR ServiceName="WCE SERVICE") OR ServiceFileName="*\\PAExec*" OR ServiceFileName="winexesvc.exe*" OR ServiceFileName="*\\DumpSvc.exe" OR ServiceName="mssecsvc2.0" OR ServiceFileName="* net user *" OR (ServiceName="pwdump*" OR ServiceName="gsecdump*" OR ServiceName="cachedump*"))) | stats values(*) AS * by _time | search NOT [| inputlookup Malicious_Service_Installations_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.privilege_escalation,sigma_tag=attack.t1050,sigma_tag=car.2013-09-005,level=critical"
```
