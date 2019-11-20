| Title                | Antivirus Web Shell Detection                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a highly relevant Antivirus alert that reports a web shell                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| Data Needed          | <ul><li>[DN_0084_av_alert](../Data_Needed/DN_0084_av_alert.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/](https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Antivirus Web Shell Detection
id: fdf135a2-9241-4f96-a114-bb404948f736
description: Detects a highly relevant Antivirus alert that reports a web shell
date: 2018/09/09
modified: 2019/10/04
author: Florian Roth
references:
    - https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/
tags:
    - attack.persistence
    - attack.t1100
logsource:
    product: antivirus
detection:
    selection:
        Signature: 
            - "PHP/Backdoor*"
            - "JSP/Backdoor*"
            - "ASP/Backdoor*"
            - "Backdoor.PHP*"
            - "Backdoor.JSP*"
            - "Backdoor.ASP*"
            - "*Webshell*"
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
(Signature="PHP/Backdoor*" OR Signature="JSP/Backdoor*" OR Signature="ASP/Backdoor*" OR Signature="Backdoor.PHP*" OR Signature="Backdoor.JSP*" OR Signature="Backdoor.ASP*" OR Signature="*Webshell*") | table FileName,User
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Antivirus Web Shell Detection]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
FileName: $result.FileName$ \
User: $result.User$  \
title: Antivirus Web Shell Detection status:  \
description: Detects a highly relevant Antivirus alert that reports a web shell \
references: ['https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/'] \
tags: ['attack.persistence', 'attack.t1100'] \
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
description = Detects a highly relevant Antivirus alert that reports a web shell
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Signature="PHP/Backdoor*" OR Signature="JSP/Backdoor*" OR Signature="ASP/Backdoor*" OR Signature="Backdoor.PHP*" OR Signature="Backdoor.JSP*" OR Signature="Backdoor.ASP*" OR Signature="*Webshell*") | table FileName,User,host | search NOT [| inputlookup Antivirus_Web_Shell_Detection_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.t1100,level=critical"
```
