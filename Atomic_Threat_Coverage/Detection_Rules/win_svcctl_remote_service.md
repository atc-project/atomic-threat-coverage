| Title                | Remote Service Activity Detected via SVCCTL named pipe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects remote remote service activity via remote access to the svcctl named pipe                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | medium |
| False Positives      | <ul><li>pentesting</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://blog.menasec.net/2019/03/threat-hunting-26-remote-windows.html](https://blog.menasec.net/2019/03/threat-hunting-26-remote-windows.html)</li></ul>  |
| Author               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Remote Service Activity Detected via SVCCTL named pipe
id: 586a8d6b-6bfe-4ad9-9d78-888cd2fe50c3
description: Detects remote remote service activity via remote access to the svcctl named pipe
author: Samir Bousseaden
references:
    - https://blog.menasec.net/2019/03/threat-hunting-26-remote-windows.html
tags:
    - attack.lateral_movement
    - attack.persistence
logsource:
    product: windows
    service: security
    description: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName: svcctl
        Accesses: '*WriteData*'
    condition: selection
falsepositives: 
    - pentesting
level: medium

```





### splunk
    
```
(EventID="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName="svcctl" Accesses="*WriteData*")
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Remote Service Activity Detected via SVCCTL named pipe]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Remote Service Activity Detected via SVCCTL named pipe status:  \\\ndescription: Detects remote remote service activity via remote access to the svcctl named pipe \\\nreferences: [\'https://blog.menasec.net/2019/03/threat-hunting-26-remote-windows.html\'] \\\ntags: [\'attack.lateral_movement\', \'attack.persistence\'] \\\nauthor: Samir Bousseaden \\\ndate:  \\\nfalsepositives: [\'pentesting\'] \\\nlevel: medium\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects remote remote service activity via remote access to the svcctl named pipe\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName="svcctl" Accesses="*WriteData*") | stats values(*) AS * by _time | search NOT [| inputlookup Remote_Service_Activity_Detected_via_SVCCTL_named_pipe_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.persistence,level=medium"\n\n\n'
```
