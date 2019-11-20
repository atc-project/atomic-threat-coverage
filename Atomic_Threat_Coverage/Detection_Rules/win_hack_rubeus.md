| Title                | Rubeus Hack Tool                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects command line parameters used by Rubeus hack tool                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/](https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>attack.s0005</li><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Rubeus Hack Tool
id: 7ec2c172-dceb-4c10-92c9-87c1881b7e18
description: Detects command line parameters used by Rubeus hack tool
author: Florian Roth
references:
    - https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/
date: 2018/12/19
tags:
    - attack.credential_access
    - attack.t1003
    - attack.s0005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* asreproast *'
            - '* dump /service:krbtgt *'
            - '* kerberoast *'
            - '* createnetonly /program:*'
            - '* ptt /ticket:*'
            - '* /impersonateuser:*'
            - '* renew /ticket:*'
            - '* asktgt /user:*'
            - '* harvest /interval:*'
    condition: selection
falsepositives:
    - unlikely
level: critical

```





### splunk
    
```
(CommandLine="* asreproast *" OR CommandLine="* dump /service:krbtgt *" OR CommandLine="* kerberoast *" OR CommandLine="* createnetonly /program:*" OR CommandLine="* ptt /ticket:*" OR CommandLine="* /impersonateuser:*" OR CommandLine="* renew /ticket:*" OR CommandLine="* asktgt /user:*" OR CommandLine="* harvest /interval:*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Rubeus Hack Tool]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Rubeus Hack Tool status:  \
description: Detects command line parameters used by Rubeus hack tool \
references: ['https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/'] \
tags: ['attack.credential_access', 'attack.t1003', 'attack.s0005'] \
author: Florian Roth \
date:  \
falsepositives: ['unlikely'] \
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
description = Detects command line parameters used by Rubeus hack tool
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="* asreproast *" OR CommandLine="* dump /service:krbtgt *" OR CommandLine="* kerberoast *" OR CommandLine="* createnetonly /program:*" OR CommandLine="* ptt /ticket:*" OR CommandLine="* /impersonateuser:*" OR CommandLine="* renew /ticket:*" OR CommandLine="* asktgt /user:*" OR CommandLine="* harvest /interval:*") | stats values(*) AS * by _time | search NOT [| inputlookup Rubeus_Hack_Tool_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,sigma_tag=attack.s0005,level=critical"
```
