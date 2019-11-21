| Title                | Pass the Hash Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the attack technique pass the hash which is used to move laterally inside the network                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li></ul>  |
| Data Needed          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1075: Pass the Hash](../Triggers/T1075.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Administrator activity</li><li>Penetration tests</li></ul>  |
| Development Status   | production |
| References           | <ul><li>[https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events](https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events)</li><li>[https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis](https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis)</li><li>[https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/](https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/)</li></ul>  |
| Author               | Dave Kennedy, Jeff Warren (method) / David Vassallo (rule) |


## Detection Rules

### Sigma rule

```
title: Pass the Hash Activity
id: 8eef149c-bd26-49f2-9e5a-9b00e3af499b
status: production
description: Detects the attack technique pass the hash which is used to move laterally inside the network
references:
    - https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events
    - https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis
    - https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/
author: Dave Kennedy, Jeff Warren (method) / David Vassallo (rule)
tags:
    - attack.lateral_movement
    - attack.t1075
logsource:
    product: windows
    service: security
    definition: The successful use of PtH for lateral movement between workstations would trigger event ID 4624
detection:
    selection:
        - EventID: 4624
          SubjectUserSid: 'S-1-0-0'
          LogonType: '3'
          LogonProcessName: 'NtLmSsp'
          KeyLength: '0'
        - EventID: 4624
          LogonType: '9'
          LogonProcessName: 'seclogo'
    filter:
        AccountName: 'ANONYMOUS LOGON'
    condition: selection and not filter
falsepositives:
    - Administrator activity
    - Penetration tests
level: medium

```





### splunk
    
```
((EventID="4624" ((SubjectUserSid="S-1-0-0" LogonType="3" LogonProcessName="NtLmSsp" KeyLength="0") OR (LogonType="9" LogonProcessName="seclogo"))) NOT (AccountName="ANONYMOUS LOGON"))
```



