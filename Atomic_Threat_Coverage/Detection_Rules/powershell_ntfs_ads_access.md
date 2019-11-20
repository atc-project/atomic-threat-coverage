| Title                | NTFS Alternate Data Stream                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1096: NTFS File Attributes](https://attack.mitre.org/techniques/T1096)</li></ul>  |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1096: NTFS File Attributes](../Triggers/T1096.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://www.powertheshell.com/ntfsstreams/](http://www.powertheshell.com/ntfsstreams/)</li></ul>  |
| Author               | Sami Ruohonen |


## Detection Rules

### Sigma rule

```
title: NTFS Alternate Data Stream
id: 8c521530-5169-495d-a199-0a3a881ad24e
status: experimental
description: Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.
references:
    - http://www.powertheshell.com/ntfsstreams/
tags:
    - attack.defense_evasion
    - attack.t1096
author: Sami Ruohonen
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    keyword1:
        - "set-content"
    keyword2:
        - "-stream"
    condition: keyword1 and keyword2
falsepositives:
    - unknown
level: high

```





### splunk
    
```
("set-content" "-stream")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[NTFS Alternate Data Stream]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: NTFS Alternate Data Stream status: experimental \
description: Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging. \
references: ['http://www.powertheshell.com/ntfsstreams/'] \
tags: ['attack.defense_evasion', 'attack.t1096'] \
author: Sami Ruohonen \
date:  \
falsepositives: ['unknown'] \
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
description = Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ("set-content" "-stream") | stats values(*) AS * by _time | search NOT [| inputlookup NTFS_Alternate_Data_Stream_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1096,level=high"
```
