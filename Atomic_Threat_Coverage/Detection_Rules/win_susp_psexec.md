| Title                | Suspicious PsExec execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li></ul>  |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1077: Windows Admin Shares](../Triggers/T1077.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>nothing observed so far</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html](https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html)</li></ul>  |
| Author               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Suspicious PsExec execution
id: c462f537-a1e3-41a6-b5fc-b2c2cef9bf82
description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker
    uses a different psexec client other than sysinternal one
author: Samir Bousseaden
references:
    - https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html
tags:
    - attack.lateral_movement
    - attack.t1077
logsource:
    product: windows
    service: security
    description: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection1:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName:
         - '*-stdin'
         - '*-stdout'
         - '*-stderr'
    selection2:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName: 'PSEXESVC*'
    condition: selection1 and not selection2
falsepositives: 
    - nothing observed so far
level: high

```





### splunk
    
```
((EventID="5145" ShareName="\\\\*\\\\IPC$" (RelativeTargetName="*-stdin" OR RelativeTargetName="*-stdout" OR RelativeTargetName="*-stderr")) NOT (EventID="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName="PSEXESVC*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious PsExec execution]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious PsExec execution status:  \
description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one \
references: ['https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html'] \
tags: ['attack.lateral_movement', 'attack.t1077'] \
author: Samir Bousseaden \
date:  \
falsepositives: ['nothing observed so far'] \
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
description = detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((EventID="5145" ShareName="\\*\\IPC$" (RelativeTargetName="*-stdin" OR RelativeTargetName="*-stdout" OR RelativeTargetName="*-stderr")) NOT (EventID="5145" ShareName="\\*\\IPC$" RelativeTargetName="PSEXESVC*")) | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_PsExec_execution_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1077,level=high"
```
