| Title                | Mimikatz DC Sync                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Mimikatz DC sync security events                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0030_4662_operation_was_performed_on_an_object](../Data_Needed/DN_0030_4662_operation_was_performed_on_an_object.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Valid DC Sync that is not covered by the filters; please report</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/gentilkiwi/status/1003236624925413376](https://twitter.com/gentilkiwi/status/1003236624925413376)</li><li>[https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2](https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2)</li></ul>  |
| Author               | Benjamin Delpy, Florian Roth |
| Other Tags           | <ul><li>attack.s0002</li><li>attack.s0002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Mimikatz DC Sync
id: 611eab06-a145-4dfa-a295-3ccc5c20f59a
description: Detects Mimikatz DC sync security events
status: experimental
date: 2018/06/03
modified: 2019/10/08
author: Benjamin Delpy, Florian Roth
references:
    - https://twitter.com/gentilkiwi/status/1003236624925413376
    - https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2
tags:
    - attack.credential_access
    - attack.s0002
    - attack.t1003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties: 
            - '*Replicating Directory Changes All*'
            - '*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*'
    filter1:
        SubjectDomainName: 'Window Manager'
    filter2: 
        SubjectUserName:
            - 'NT AUTHORITY*'
            - '*$'
    condition: selection and not filter1 and not filter2
falsepositives:
    - Valid DC Sync that is not covered by the filters; please report
level: high


```





### splunk
    
```
(((EventID="4662" (Properties="*Replicating Directory Changes All*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")) NOT (SubjectDomainName="Window Manager")) NOT ((SubjectUserName="NT AUTHORITY*" OR SubjectUserName="*$")))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Mimikatz DC Sync]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Mimikatz DC Sync status: experimental \\\ndescription: Detects Mimikatz DC sync security events \\\nreferences: [\'https://twitter.com/gentilkiwi/status/1003236624925413376\', \'https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2\'] \\\ntags: [\'attack.credential_access\', \'attack.s0002\', \'attack.t1003\'] \\\nauthor: Benjamin Delpy, Florian Roth \\\ndate:  \\\nfalsepositives: [\'Valid DC Sync that is not covered by the filters; please report\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects Mimikatz DC sync security events\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (((EventID="4662" (Properties="*Replicating Directory Changes All*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")) NOT (SubjectDomainName="Window Manager")) NOT ((SubjectUserName="NT AUTHORITY*" OR SubjectUserName="*$"))) | stats values(*) AS * by _time | search NOT [| inputlookup Mimikatz_DC_Sync_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.s0002,sigma_tag=attack.t1003,level=high"\n\n\n'
```
