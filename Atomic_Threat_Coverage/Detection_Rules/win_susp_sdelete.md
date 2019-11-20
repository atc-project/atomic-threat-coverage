| Title                | Secure Deletion with SDelete                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects renaming of file while deletion with SDelete tool                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1107: File Deletion](https://attack.mitre.org/techniques/T1107)</li><li>[T1066: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1066)</li></ul>  |
| Data Needed          | <ul><li>[DN_0060_4658_handle_to_an_object_was_closed](../Data_Needed/DN_0060_4658_handle_to_an_object_was_closed.md)</li><li>[DN_0062_4663_attempt_was_made_to_access_an_object](../Data_Needed/DN_0062_4663_attempt_was_made_to_access_an_object.md)</li><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1107: File Deletion](../Triggers/T1107.md)</li><li>[T1066: Indicator Removal from Tools](../Triggers/T1066.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitime usage of SDelete</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)</li><li>[https://www.jpcert.or.jp/english/pub/sr/ir_research.html](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)</li><li>[https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx](https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx)</li></ul>  |
| Author               | Thomas Patzke |
| Other Tags           | <ul><li>attack.s0195</li><li>attack.s0195</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Secure Deletion with SDelete
id: 39a80702-d7ca-4a83-b776-525b1f86a36d
status: experimental
description: Detects renaming of file while deletion with SDelete tool
author: Thomas Patzke
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx
tags:
    - attack.defense_evasion
    - attack.t1107
    - attack.t1066
    - attack.s0195
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4663
            - 4658
        ObjectName:
            - '*.AAA'
            - '*.ZZZ'
    condition: selection
falsepositives:
    - Legitime usage of SDelete
level: medium

```





### splunk
    
```
((EventID="4656" OR EventID="4663" OR EventID="4658") (ObjectName="*.AAA" OR ObjectName="*.ZZZ"))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Secure Deletion with SDelete]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Secure Deletion with SDelete status: experimental \\\ndescription: Detects renaming of file while deletion with SDelete tool \\\nreferences: [\'https://jpcertcc.github.io/ToolAnalysisResultSheet\', \'https://www.jpcert.or.jp/english/pub/sr/ir_research.html\', \'https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx\'] \\\ntags: [\'attack.defense_evasion\', \'attack.t1107\', \'attack.t1066\', \'attack.s0195\'] \\\nauthor: Thomas Patzke \\\ndate:  \\\nfalsepositives: [\'Legitime usage of SDelete\'] \\\nlevel: medium\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects renaming of file while deletion with SDelete tool\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = ((EventID="4656" OR EventID="4663" OR EventID="4658") (ObjectName="*.AAA" OR ObjectName="*.ZZZ")) | stats values(*) AS * by _time | search NOT [| inputlookup Secure_Deletion_with_SDelete_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1107,sigma_tag=attack.t1066,sigma_tag=attack.s0195,level=medium"\n\n\n'
```
