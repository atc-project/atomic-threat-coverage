| Title                | Possible SPN Enumeration                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Service Principal Name Enumeration used for Kerberoasting                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1208: Kerberoasting](https://attack.mitre.org/techniques/T1208)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1208: Kerberoasting](../Triggers/T1208.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Administrator Activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation](https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation)</li></ul>  |
| Author               | Markus Neis, keepwatch |


## Detection Rules

### Sigma rule

```
title: Possible SPN Enumeration
id: 1eeed653-dbc8-4187-ad0c-eeebb20e6599
description: Detects Service Principal Name Enumeration used for Kerberoasting
status: experimental
references:
    - https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation
author: Markus Neis, keepwatch
date: 2018/11/14
tags:
    - attack.credential_access
    - attack.t1208
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image: '*\setspn.exe'
    selection_desc:
        Description: '*Query or reset the computer* SPN attribute*'
    cmd:
        CommandLine: '*-q*'
    condition: (selection_image or selection_desc) and cmd
falsepositives:
    - Administrator Activity
level: medium

```





### splunk
    
```
((Image="*\\\\setspn.exe" OR Description="*Query or reset the computer* SPN attribute*") CommandLine="*-q*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Possible SPN Enumeration]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Possible SPN Enumeration status: experimental \
description: Detects Service Principal Name Enumeration used for Kerberoasting \
references: ['https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation'] \
tags: ['attack.credential_access', 'attack.t1208'] \
author: Markus Neis, keepwatch \
date:  \
falsepositives: ['Administrator Activity'] \
level: medium
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects Service Principal Name Enumeration used for Kerberoasting
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\setspn.exe" OR Description="*Query or reset the computer* SPN attribute*") CommandLine="*-q*") | stats values(*) AS * by _time | search NOT [| inputlookup Possible_SPN_Enumeration_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1208,level=medium"
```
