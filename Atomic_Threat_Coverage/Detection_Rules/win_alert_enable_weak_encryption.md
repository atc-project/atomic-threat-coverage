| Title                | Weak Encryption Enabled and Kerberoast                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| Data Needed          | <ul><li>[DN_0027_4738_user_account_was_changed](../Data_Needed/DN_0027_4738_user_account_was_changed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://adsecurity.org/?p=2053](https://adsecurity.org/?p=2053)</li><li>[https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)</li></ul>  |
| Author               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Weak Encryption Enabled and Kerberoast
id: f6de9536-0441-4b3f-a646-f4e00f300ffd
description: Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.
references:
    - https://adsecurity.org/?p=2053
    - https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/
author: '@neu5ron'
tags:
    - attack.defense_evasion
    - attack.t1089
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Account Management > Audit User Account Management, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management\Audit User Account Management'
detection:
    selection:
        EventID: 4738
    keywords:
        Message:
        - '*DES*'
        - '*Preauth*'
        - '*Encrypted*'
    filters:
        Message:
            - '*Enabled*'
    condition: selection and keywords and filters
falsepositives: 
    - Unknown
level: high

```





### splunk
    
```
(EventID="4738" (Message="*DES*" OR Message="*Preauth*" OR Message="*Encrypted*") (Message="*Enabled*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Weak Encryption Enabled and Kerberoast]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Weak Encryption Enabled and Kerberoast status:  \
description: Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking. \
references: ['https://adsecurity.org/?p=2053', 'https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/'] \
tags: ['attack.defense_evasion', 'attack.t1089'] \
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
description = Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="4738" (Message="*DES*" OR Message="*Preauth*" OR Message="*Encrypted*") (Message="*Enabled*")) | stats values(*) AS * by _time | search NOT [| inputlookup Weak_Encryption_Enabled_and_Kerberoast_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1089,level=high"
```
