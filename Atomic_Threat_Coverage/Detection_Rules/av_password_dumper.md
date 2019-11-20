| Title                | Antivirus Password Dumper Detection                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a highly relevant Antivirus alert that reports a password dumper                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0084_av_alert](../Data_Needed/DN_0084_av_alert.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/](https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Antivirus Password Dumper Detection
id: 78cc2dd2-7d20-4d32-93ff-057084c38b93
description: Detects a highly relevant Antivirus alert that reports a password dumper
date: 2018/09/09
modified: 2019/10/04
author: Florian Roth
references:
    - https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: antivirus
detection:
    selection:
        Signature: 
            - "*DumpCreds*"
            - "*Mimikatz*"
            - "*PWCrack*"
            - "HTool/WCE"
            - "*PSWtool*"
            - "*PWDump*"
            - "*SecurityTool*"
            - "*PShlSpy*"
    condition: selection
fields:
    - FileName
    - User
falsepositives:
    - Unlikely
level: critical

```





### splunk
    
```
(Signature="*DumpCreds*" OR Signature="*Mimikatz*" OR Signature="*PWCrack*" OR Signature="HTool/WCE" OR Signature="*PSWtool*" OR Signature="*PWDump*" OR Signature="*SecurityTool*" OR Signature="*PShlSpy*") | table FileName,User
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Antivirus Password Dumper Detection]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
FileName: $result.FileName$ \
User: $result.User$  \
title: Antivirus Password Dumper Detection status:  \
description: Detects a highly relevant Antivirus alert that reports a password dumper \
references: ['https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/'] \
tags: ['attack.credential_access', 'attack.t1003'] \
author: Florian Roth \
date:  \
falsepositives: ['Unlikely'] \
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
description = Detects a highly relevant Antivirus alert that reports a password dumper
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Signature="*DumpCreds*" OR Signature="*Mimikatz*" OR Signature="*PWCrack*" OR Signature="HTool/WCE" OR Signature="*PSWtool*" OR Signature="*PWDump*" OR Signature="*SecurityTool*" OR Signature="*PShlSpy*") | table FileName,User,host | search NOT [| inputlookup Antivirus_Password_Dumper_Detection_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,level=critical"
```
