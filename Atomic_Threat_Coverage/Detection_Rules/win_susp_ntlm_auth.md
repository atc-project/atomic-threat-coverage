| Title                | NTLM Logon                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects logons using NTLM, which could be caused by a legacy source or attackers                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li></ul>  |
| Data Needed          | <ul><li>[DN_0082_8002_ntlm_server_blocked_audit](../Data_Needed/DN_0082_8002_ntlm_server_blocked_audit.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1075: Pass the Hash](../Triggers/T1075.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Legacy hosts</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/JohnLaTwC/status/1004895028995477505](https://twitter.com/JohnLaTwC/status/1004895028995477505)</li><li>[https://goo.gl/PsqrhT](https://goo.gl/PsqrhT)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: NTLM Logon
id: 98c3bcf1-56f2-49dc-9d8d-c66cf190238b
status: experimental
description: Detects logons using NTLM, which could be caused by a legacy source or attackers
references:
    - https://twitter.com/JohnLaTwC/status/1004895028995477505
    - https://goo.gl/PsqrhT
author: Florian Roth
date: 2018/06/08
tags:
    - attack.lateral_movement
    - attack.t1075
logsource:
    product: windows
    service: ntlm
    definition: Reqiures events from Microsoft-Windows-NTLM/Operational
detection:
    selection:
        EventID: 8002
        CallingProcessName: '*'  # We use this to avoid false positives with ID 8002 on other log sources if the logsource isn't set correctly
    condition: selection
falsepositives:
    - Legacy hosts
level: low

```





### splunk
    
```
(EventID="8002" CallingProcessName="*")
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[NTLM Logon]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: NTLM Logon status: experimental \\\ndescription: Detects logons using NTLM, which could be caused by a legacy source or attackers \\\nreferences: [\'https://twitter.com/JohnLaTwC/status/1004895028995477505\', \'https://goo.gl/PsqrhT\'] \\\ntags: [\'attack.lateral_movement\', \'attack.t1075\'] \\\nauthor: Florian Roth \\\ndate:  \\\nfalsepositives: [\'Legacy hosts\'] \\\nlevel: low\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects logons using NTLM, which could be caused by a legacy source or attackers\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="8002" CallingProcessName="*") | stats values(*) AS * by _time | search NOT [| inputlookup NTLM_Logon_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1075,level=low"\n\n\n'
```
