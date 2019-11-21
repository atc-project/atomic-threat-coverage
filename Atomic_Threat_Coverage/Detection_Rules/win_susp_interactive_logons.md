| Title                | Interactive Logon to Server Systems                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects interactive console logons to                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| Data Needed          | <ul><li>[DN_0041_529_logon_failure](../Data_Needed/DN_0041_529_logon_failure.md)</li><li>[DN_0040_528_user_successfully_logged_on_to_a_computer](../Data_Needed/DN_0040_528_user_successfully_logged_on_to_a_computer.md)</li><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Administrative activity via KVM or ILO board</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Interactive Logon to Server Systems
id: 3ff152b2-1388-4984-9cd9-a323323fdadf
description: Detects interactive console logons to
author: Florian Roth
tags:
    - attack.lateral_movement
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 528
            - 529
            - 4624
            - 4625
        LogonType: 2
        ComputerName:
            - '%ServerSystems%'
            - '%DomainControllers%'
    filter:
        LogonProcessName: Advapi
        ComputerName: '%Workstations%'
    condition: selection and not filter
falsepositives:
    - Administrative activity via KVM or ILO board
level: medium



```





### splunk
    
```
(((EventID="528" OR EventID="529" OR EventID="4624" OR EventID="4625") LogonType="2" (ComputerName="%ServerSystems%" OR ComputerName="%DomainControllers%")) NOT (LogonProcessName="Advapi" ComputerName="%Workstations%"))
```



