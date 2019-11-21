| Title                | Malicious Service Install                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This method detects well-known keywords of malicious services in the Windows System Eventlog                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0083_16_access_history_in_hive_was_cleared](../Data_Needed/DN_0083_16_access_history_in_hive_was_cleared.md)</li><li>[DN_0063_4697_service_was_installed_in_the_system](../Data_Needed/DN_0063_4697_service_was_installed_in_the_system.md)</li><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
action: global
title: Malicious Service Install
id: 4976aa50-8f41-45c6-8b15-ab3fc10e79ed
description: This method detects well-known keywords of malicious services in the Windows System Eventlog
author: Florian Roth
tags:
    - attack.credential_access
    - attack.t1003
    - attack.s0005
logsource:
    product: windows
    service: system
detection:
    selection1:
        EventID: 
          - 7045
    keywords:
        Message:
          - '*WCE SERVICE*'
          - '*WCESERVICE*'
          - '*DumpSvc*'
    quarkspwdump:
        EventID: 16
        HiveName: '*\AppData\Local\Temp\SAM*.dmp'
    condition: ( selection1 and keywords ) or ( selection2 and keywords ) or quarkspwdump
falsepositives:
    - Unlikely
level: high
---
logsource:
    product: windows
    service: security
detection:
    selection2:
        EventID: 4697

```





### splunk
    
```
(((Message="*WCE SERVICE*" OR Message="*WCESERVICE*" OR Message="*DumpSvc*") ((EventID="7045") OR EventID="4697")) OR (EventID="16" HiveName="*\\\\AppData\\\\Local\\\\Temp\\\\SAM*.dmp"))
```



