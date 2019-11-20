| Title                | SAM Dump to AppData                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0083_16_access_history_in_hive_was_cleared](../Data_Needed/DN_0083_16_access_history_in_hive_was_cleared.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration testing</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: SAM Dump to AppData
id: 839dd1e8-eda8-4834-8145-01beeee33acd
status: experimental
description: Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers
tags:
    - attack.credential_access
    - attack.t1003
author: Florian Roth
logsource:
    product: windows
    service: system
    definition: The source of this type of event is Kernel-General
detection:
    selection:
        EventID: 16
    keywords:
        Message:
            - '*\AppData\Local\Temp\SAM-*.dmp *'
    condition: all of them
falsepositives:
    - Penetration testing
level: high

```





### splunk
    
```
(EventID="16" (Message="*\\\\AppData\\\\Local\\\\Temp\\\\SAM-*.dmp *"))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[SAM Dump to AppData]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: SAM Dump to AppData status: experimental \\\ndescription: Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers \\\nreferences:  \\\ntags: [\'attack.credential_access\', \'attack.t1003\'] \\\nauthor: Florian Roth \\\ndate:  \\\nfalsepositives: [\'Penetration testing\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="16" (Message="*\\\\AppData\\\\Local\\\\Temp\\\\SAM-*.dmp *")) | stats values(*) AS * by _time | search NOT [| inputlookup SAM_Dump_to_AppData_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,level=high"\n\n\n'
```
