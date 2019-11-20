| Title                | Disabling Windows Event Auditing                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario where an entity would want to bypass local logging to evade detection when windows event logging is enabled and reviewed. Also, it is recommended to turn off "Local Group Policy Object Processing" via GPO, which will make sure that Active Directory GPOs take precedence over local/edited computer policies via something such as "gpedit.msc". Please note, that disabling "Local Group Policy Object Processing" may cause an issue in scenarios of one off specific GPO modifications -- however it is recommended to perform these modifications in Active Directory anyways.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1054: Indicator Blocking](https://attack.mitre.org/techniques/T1054)</li></ul>  |
| Data Needed          | <ul><li>[DN_0067_4719_system_audit_policy_was_changed](../Data_Needed/DN_0067_4719_system_audit_policy_was_changed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1054: Indicator Blocking](../Triggers/T1054.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://bit.ly/WinLogsZero2Hero](https://bit.ly/WinLogsZero2Hero)</li></ul>  |
| Author               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Disabling Windows Event Auditing
id: 69aeb277-f15f-4d2d-b32a-55e883609563
description: 'Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario where an entity would want to bypass
    local logging to evade detection when windows event logging is enabled and reviewed. Also, it is recommended to turn off "Local Group Policy Object Processing"
    via GPO, which will make sure that Active Directory GPOs take precedence over local/edited computer policies via something such as "gpedit.msc". Please note,
    that disabling "Local Group Policy Object Processing" may cause an issue in scenarios of one off specific GPO modifications -- however it is recommended to perform
    these modifications in Active Directory anyways.'
references:
    - https://bit.ly/WinLogsZero2Hero
tags:
    - attack.defense_evasion
    - attack.t1054
author: '@neu5ron'
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Computer Management > Audit Policy Configuration, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Authorization Policy Change'
detection:
    selection:
        EventID: 4719
        AuditPolicyChanges: 'removed'
    condition: selection
falsepositives: 
    - Unknown
level: high

```





### splunk
    
```
(EventID="4719" AuditPolicyChanges="removed")
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Disabling Windows Event Auditing]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Disabling Windows Event Auditing status:  \\\ndescription: Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario where an entity would want to bypass local logging to evade detection when windows event logging is enabled and reviewed. Also, it is recommended to turn off "Local Group Policy Object Processing" via GPO, which will make sure that Active Directory GPOs take precedence over local/edited computer policies via something such as "gpedit.msc". Please note, that disabling "Local Group Policy Object Processing" may cause an issue in scenarios of one off specific GPO modifications -- however it is recommended to perform these modifications in Active Directory anyways. \\\nreferences: [\'https://bit.ly/WinLogsZero2Hero\'] \\\ntags: [\'attack.defense_evasion\', \'attack.t1054\'] \\\nauthor: @neu5ron \\\ndate:  \\\nfalsepositives: [\'Unknown\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario where an entity would want to bypass local logging to evade detection when windows event logging is enabled and reviewed. Also, it is recommended to turn off "Local Group Policy Object Processing" via GPO, which will make sure that Active Directory GPOs take precedence over local/edited computer policies via something such as "gpedit.msc". Please note, that disabling "Local Group Policy Object Processing" may cause an issue in scenarios of one off specific GPO modifications -- however it is recommended to perform these modifications in Active Directory anyways.\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="4719" AuditPolicyChanges="removed") | stats values(*) AS * by _time | search NOT [| inputlookup Disabling_Windows_Event_Auditing_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1054,level=high"\n\n\n'
```
