| Title                | Active Directory User Backdoors                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects scenarios where one can control another users or computers account without having to use their credentials.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098)</li></ul>  |
| Data Needed          | <ul><li>[DN_0026_5136_windows_directory_service_object_was_modified](../Data_Needed/DN_0026_5136_windows_directory_service_object_was_modified.md)</li><li>[DN_0027_4738_user_account_was_changed](../Data_Needed/DN_0027_4738_user_account_was_changed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1098: Account Manipulation](../Triggers/T1098.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://msdn.microsoft.com/en-us/library/cc220234.aspx](https://msdn.microsoft.com/en-us/library/cc220234.aspx)</li><li>[https://adsecurity.org/?p=3466](https://adsecurity.org/?p=3466)</li><li>[https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)</li></ul>  |
| Author               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Active Directory User Backdoors
id: 300bac00-e041-4ee2-9c36-e262656a6ecc
description: Detects scenarios where one can control another users or computers account without having to use their credentials.
references:
    - https://msdn.microsoft.com/en-us/library/cc220234.aspx
    - https://adsecurity.org/?p=3466
    - https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/
author: '@neu5ron'
tags:
    - attack.t1098
    - attack.credential_access
    - attack.persistence
logsource:
    product: windows
    service: security
    definition1: 'Requirements: Audit Policy : Account Management > Audit User Account Management, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management\Audit User Account Management'
    definition2: 'Requirements: Audit Policy : DS Access > Audit Directory Service Changes, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\DS Access\Audit Directory Service Changes'
detection:
    selection1:
        EventID: 4738
    filter1:
        AllowedToDelegateTo: null
    filter2:
        AllowedToDelegateTo: '-'
    selection2:
        EventID: 5136
        AttributeLDAPDisplayName: 'msDS-AllowedToDelegateTo'
    selection3:
        EventID: 5136
        ObjectClass: 'user'
        AttributeLDAPDisplayName: 'servicePrincipalName'
    selection4:
        EventID: 5136
        AttributeLDAPDisplayName: 'msDS-AllowedToActOnBehalfOfOtherIdentity'        
    condition: (selection1 and not 1 of filter*) or selection2 or selection3 or selection4
falsepositives: 
    - Unknown
level: high

```





### splunk
    
```
((((EventID="4738" NOT ((NOT AllowedToDelegateTo="*") OR (AllowedToDelegateTo="-"))) OR (EventID="5136" AttributeLDAPDisplayName="msDS-AllowedToDelegateTo")) OR (EventID="5136" ObjectClass="user" AttributeLDAPDisplayName="servicePrincipalName")) OR (EventID="5136" AttributeLDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Active Directory User Backdoors]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Active Directory User Backdoors status:  \
description: Detects scenarios where one can control another users or computers account without having to use their credentials. \
references: ['https://msdn.microsoft.com/en-us/library/cc220234.aspx', 'https://adsecurity.org/?p=3466', 'https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/'] \
tags: ['attack.t1098', 'attack.credential_access', 'attack.persistence'] \
author: @neu5ron \
date:  \
falsepositives: ['Unknown'] \
level: high
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects scenarios where one can control another users or computers account without having to use their credentials.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((((EventID="4738" NOT ((NOT AllowedToDelegateTo="*") OR (AllowedToDelegateTo="-"))) OR (EventID="5136" AttributeLDAPDisplayName="msDS-AllowedToDelegateTo")) OR (EventID="5136" ObjectClass="user" AttributeLDAPDisplayName="servicePrincipalName")) OR (EventID="5136" AttributeLDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity")) | stats values(*) AS * by _time | search NOT [| inputlookup Active_Directory_User_Backdoors_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.t1098,sigma_tag=attack.credential_access,sigma_tag=attack.persistence,level=high"
```
