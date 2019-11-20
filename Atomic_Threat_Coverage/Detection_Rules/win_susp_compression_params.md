| Title                | Suspicious Compression Tool Parameters                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious command line arguments of common data compression tools                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020)</li><li>[T1002: Data Compressed](https://attack.mitre.org/techniques/T1002)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1020: Automated Exfiltration](../Triggers/T1020.md)</li><li>[T1002: Data Compressed](../Triggers/T1002.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/SBousseaden/status/1184067445612535811](https://twitter.com/SBousseaden/status/1184067445612535811)</li></ul>  |
| Author               | Florian Roth, Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Suspicious Compression Tool Parameters
id: 27a72a60-7e5e-47b1-9d17-909c9abafdcd
status: experimental
description: Detects suspicious command line arguments of common data compression tools
references:
    - https://twitter.com/SBousseaden/status/1184067445612535811
tags:
    - attack.exfiltration
    - attack.t1020
    - attack.t1002
author: Florian Roth, Samir Bousseaden
date: 2019/10/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName:
            - '7z*.exe'
            - '*rar.exe'
            - '*Command*Line*RAR*'
        CommandLine:
            - '* -p*'
            - '* -ta*'
            - '* -tb*'
            - '* -sdel*'
            - '* -dw*'
            - '* -hp*'
    falsepositive:
        ParentImage: 'C:\Program*'
    condition: selection and not falsepositive
falsepositives:
    - unknown
level: high

```





### splunk
    
```
(((OriginalFileName="7z*.exe" OR OriginalFileName="*rar.exe" OR OriginalFileName="*Command*Line*RAR*") (CommandLine="* -p*" OR CommandLine="* -ta*" OR CommandLine="* -tb*" OR CommandLine="* -sdel*" OR CommandLine="* -dw*" OR CommandLine="* -hp*")) NOT (ParentImage="C:\\\\Program*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious Compression Tool Parameters]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious Compression Tool Parameters status: experimental \
description: Detects suspicious command line arguments of common data compression tools \
references: ['https://twitter.com/SBousseaden/status/1184067445612535811'] \
tags: ['attack.exfiltration', 'attack.t1020', 'attack.t1002'] \
author: Florian Roth, Samir Bousseaden \
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
description = Detects suspicious command line arguments of common data compression tools
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (((OriginalFileName="7z*.exe" OR OriginalFileName="*rar.exe" OR OriginalFileName="*Command*Line*RAR*") (CommandLine="* -p*" OR CommandLine="* -ta*" OR CommandLine="* -tb*" OR CommandLine="* -sdel*" OR CommandLine="* -dw*" OR CommandLine="* -hp*")) NOT (ParentImage="C:\\Program*")) | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_Compression_Tool_Parameters_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.exfiltration,sigma_tag=attack.t1020,sigma_tag=attack.t1002,level=high"
```
