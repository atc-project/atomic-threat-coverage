| Title                | Possible Impacket SecretDump remote activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detect AD credential dumping using impacket secretdump HKTL                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>pentesting</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html](https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html)</li></ul>  |
| Author               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Possible Impacket SecretDump remote activity
id: 252902e3-5830-4cf6-bf21-c22083dfd5cf
description: Detect AD credential dumping using impacket secretdump HKTL
author: Samir Bousseaden
references:
    - https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: security
    description: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\ADMIN$
        RelativeTargetName: 'SYSTEM32\\*.tmp'
    condition: selection
falsepositives: 
    - pentesting
level: high

```





### splunk
    
```
(EventID="5145" ShareName="\\\\*\\\\ADMIN$" RelativeTargetName="SYSTEM32\\\\*.tmp")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Possible Impacket SecretDump remote activity]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Possible Impacket SecretDump remote activity status:  \
description: Detect AD credential dumping using impacket secretdump HKTL \
references: ['https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html'] \
tags: ['attack.credential_access', 'attack.t1003'] \
author: Samir Bousseaden \
date:  \
falsepositives: ['pentesting'] \
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
description = Detect AD credential dumping using impacket secretdump HKTL
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="5145" ShareName="\\*\\ADMIN$" RelativeTargetName="SYSTEM32\\*.tmp") | stats values(*) AS * by _time | search NOT [| inputlookup Possible_Impacket_SecretDump_remote_activity_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,level=high"
```
