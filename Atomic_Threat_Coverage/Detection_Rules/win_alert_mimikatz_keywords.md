| Title                | Mimikatz Use                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Naughty administrators</li><li>Penetration test</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>attack.s0002</li><li>attack.s0002</li><li>car.2013-07-001</li><li>car.2013-07-001</li><li>car.2019-04-004</li><li>car.2019-04-004</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Mimikatz Use
id: 06d71506-7beb-4f22-8888-e2e5e2ca7fd8
description: This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different
    threat groups)
author: Florian Roth
date: 2017/01/10
modified: 2019/10/11
tags:
    - attack.s0002
    - attack.t1003
    - attack.lateral_movement
    - attack.credential_access
    - car.2013-07-001
    - car.2019-04-004
logsource:
    product: windows
detection:
    keywords:
        Message:
        - "* mimikatz *"
        - "* mimilib *"
        - "* <3 eo.oe *"
        - "* eo.oe.kiwi *"
        - "* privilege::debug *"
        - "* sekurlsa::logonpasswords *"
        - "* lsadump::sam *"
        - "* mimidrv.sys *"
        - "* p::d *"
        - "* s::l *"
    condition: keywords
falsepositives:
    - Naughty administrators
    - Penetration test
level: critical

```





### splunk
    
```
(Message="* mimikatz *" OR Message="* mimilib *" OR Message="* <3 eo.oe *" OR Message="* eo.oe.kiwi *" OR Message="* privilege::debug *" OR Message="* sekurlsa::logonpasswords *" OR Message="* lsadump::sam *" OR Message="* mimidrv.sys *" OR Message="* p::d *" OR Message="* s::l *")
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Mimikatz Use]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Mimikatz Use status:  \\\ndescription: This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups) \\\nreferences:  \\\ntags: [\'attack.s0002\', \'attack.t1003\', \'attack.lateral_movement\', \'attack.credential_access\', \'car.2013-07-001\', \'car.2019-04-004\'] \\\nauthor: Florian Roth \\\ndate:  \\\nfalsepositives: [\'Naughty administrators\', \'Penetration test\'] \\\nlevel: critical\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (Message="* mimikatz *" OR Message="* mimilib *" OR Message="* <3 eo.oe *" OR Message="* eo.oe.kiwi *" OR Message="* privilege::debug *" OR Message="* sekurlsa::logonpasswords *" OR Message="* lsadump::sam *" OR Message="* mimidrv.sys *" OR Message="* p::d *" OR Message="* s::l *") | stats values(*) AS * by _time | search NOT [| inputlookup Mimikatz_Use_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.s0002,sigma_tag=attack.t1003,sigma_tag=attack.lateral_movement,sigma_tag=attack.credential_access,sigma_tag=car.2013-07-001,sigma_tag=car.2019-04-004,level=critical"\n\n\n'
```
