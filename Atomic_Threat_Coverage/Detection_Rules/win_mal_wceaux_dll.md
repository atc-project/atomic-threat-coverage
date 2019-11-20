| Title                | WCE wceaux.dll Access                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0060_4658_handle_to_an_object_was_closed](../Data_Needed/DN_0060_4658_handle_to_an_object_was_closed.md)</li><li>[DN_0061_4660_object_was_deleted](../Data_Needed/DN_0061_4660_object_was_deleted.md)</li><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li><li>[DN_0062_4663_attempt_was_made_to_access_an_object](../Data_Needed/DN_0062_4663_attempt_was_made_to_access_an_object.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Penetration testing</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.jpcert.or.jp/english/pub/sr/ir_research.html](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)</li><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)</li></ul>  |
| Author               | Thomas Patzke |
| Other Tags           | <ul><li>attack.s0005</li><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: WCE wceaux.dll Access
id: 1de68c67-af5c-4097-9c85-fe5578e09e67
status: experimental
description: Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host
author: Thomas Patzke
references:
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
tags:
    - attack.credential_access
    - attack.t1003
    - attack.s0005
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4658
            - 4660
            - 4663
        ObjectName: '*\wceaux.dll'
    condition: selection
falsepositives: 
    - Penetration testing
level: critical

```





### splunk
    
```
((EventID="4656" OR EventID="4658" OR EventID="4660" OR EventID="4663") ObjectName="*\\\\wceaux.dll")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[WCE wceaux.dll Access]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: WCE wceaux.dll Access status: experimental \
description: Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host \
references: ['https://www.jpcert.or.jp/english/pub/sr/ir_research.html', 'https://jpcertcc.github.io/ToolAnalysisResultSheet'] \
tags: ['attack.credential_access', 'attack.t1003', 'attack.s0005'] \
author: Thomas Patzke \
date:  \
falsepositives: ['Penetration testing'] \
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
description = Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((EventID="4656" OR EventID="4658" OR EventID="4660" OR EventID="4663") ObjectName="*\\wceaux.dll") | stats values(*) AS * by _time | search NOT [| inputlookup WCE_wceaux.dll_Access_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,sigma_tag=attack.s0005,level=critical"
```
