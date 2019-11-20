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
b'# Generated with Sigma2SplunkAlert\n[Possible Impacket SecretDump remote activity]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Possible Impacket SecretDump remote activity status:  \\\ndescription: Detect AD credential dumping using impacket secretdump HKTL \\\nreferences: [\'https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html\'] \\\ntags: [\'attack.credential_access\', \'attack.t1003\'] \\\nauthor: Samir Bousseaden \\\ndate:  \\\nfalsepositives: [\'pentesting\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detect AD credential dumping using impacket secretdump HKTL\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="5145" ShareName="\\\\*\\\\ADMIN$" RelativeTargetName="SYSTEM32\\\\*.tmp") | stats values(*) AS * by _time | search NOT [| inputlookup Possible_Impacket_SecretDump_remote_activity_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,level=high"\n\n\n'
```
