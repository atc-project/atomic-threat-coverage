| Title                | smbexec.py Service Installation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the use of smbexec.py tool by detecting a specific service installation                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li></ul>  |
| Data Needed          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1077: Windows Admin Shares](../Triggers/T1077.md)</li><li>[T1035: Service Execution](../Triggers/T1035.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Penetration Test</li><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)</li></ul>  |
| Author               | Omer Faruk Celik |


## Detection Rules

### Sigma rule

```
title: smbexec.py Service Installation
id: 52a85084-6989-40c3-8f32-091e12e13f09
description: Detects the use of smbexec.py tool by detecting a specific service installation
author: Omer Faruk Celik
date: 2018/03/20
references:
    - https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/
tags:
    - attack.lateral_movement
    - attack.execution
    - attack.t1077
    - attack.t1035
logsource:
    product: windows
    service: system
detection:
    service_installation:
        EventID: 7045
        ServiceName: 'BTOBTO'
        ServiceFileName: '*\execute.bat'
    condition: service_installation
fields:
    - ServiceName
    - ServiceFileName
falsepositives:
    - Penetration Test
    - Unknown
level: critical
```





### splunk
    
```
(EventID="7045" ServiceName="BTOBTO" ServiceFileName="*\\\\execute.bat") | table ServiceName,ServiceFileName
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[smbexec.py Service Installation]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
ServiceName: $result.ServiceName$ \
ServiceFileName: $result.ServiceFileName$  \
title: smbexec.py Service Installation status:  \
description: Detects the use of smbexec.py tool by detecting a specific service installation \
references: ['https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/'] \
tags: ['attack.lateral_movement', 'attack.execution', 'attack.t1077', 'attack.t1035'] \
author: Omer Faruk Celik \
date:  \
falsepositives: ['Penetration Test', 'Unknown'] \
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
description = Detects the use of smbexec.py tool by detecting a specific service installation
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="7045" ServiceName="BTOBTO" ServiceFileName="*\\execute.bat") | table ServiceName,ServiceFileName,host | search NOT [| inputlookup smbexec.py_Service_Installation_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.execution,sigma_tag=attack.t1077,sigma_tag=attack.t1035,level=critical"
```
