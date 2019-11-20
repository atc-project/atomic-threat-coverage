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
b'# Generated with Sigma2SplunkAlert\n[Weak Encryption Enabled and Kerberoast]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Weak Encryption Enabled and Kerberoast status:  \\\ndescription: Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking. \\\nreferences: [\'https://adsecurity.org/?p=2053\', \'https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/\'] \\\ntags: [\'attack.defense_evasion\', \'attack.t1089\'] \\\nauthor: @neu5ron \\\ndate:  \\\nfalsepositives: [\'Unknown\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="4738" (Message="*DES*" OR Message="*Preauth*" OR Message="*Encrypted*") (Message="*Enabled*")) | stats values(*) AS * by _time | search NOT [| inputlookup Weak_Encryption_Enabled_and_Kerberoast_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1089,level=high"\n\n\n'
```
