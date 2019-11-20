| Title                | Suspicious access to sensitive file extensions                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects known sensitive file extensions                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0009: Collection](https://attack.mitre.org/tactics/TA0009)</li></ul>  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>Help Desk operator doing backup or re-imaging end user machine or pentest or backup software</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Suspicious access to sensitive file extensions
id: 91c945bc-2ad1-4799-a591-4d00198a1215
description: Detects known sensitive file extensions
author: Samir Bousseaden
tags:
    - attack.collection
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 5145
        RelativeTargetName:
            - '*.pst'
            - '*.ost'
            - '*.msg'
            - '*.nst'
            - '*.oab'
            - '*.edb'
            - '*.nsf' 
            - '*.bak'
            - '*.dmp'
            - '*.kirbi'
            - '*\ntds.dit'
            - '*\groups.xml'
            - '*.rdp'
    condition: selection
falsepositives:
    - Help Desk operator doing backup or re-imaging end user machine or pentest or backup software
level: high

```





### splunk
    
```
((EventID="5145") (RelativeTargetName="*.pst" OR RelativeTargetName="*.ost" OR RelativeTargetName="*.msg" OR RelativeTargetName="*.nst" OR RelativeTargetName="*.oab" OR RelativeTargetName="*.edb" OR RelativeTargetName="*.nsf" OR RelativeTargetName="*.bak" OR RelativeTargetName="*.dmp" OR RelativeTargetName="*.kirbi" OR RelativeTargetName="*\\\\ntds.dit" OR RelativeTargetName="*\\\\groups.xml" OR RelativeTargetName="*.rdp"))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Suspicious access to sensitive file extensions]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Suspicious access to sensitive file extensions status:  \\\ndescription: Detects known sensitive file extensions \\\nreferences:  \\\ntags: [\'attack.collection\'] \\\nauthor: Samir Bousseaden \\\ndate:  \\\nfalsepositives: [\'Help Desk operator doing backup or re-imaging end user machine or pentest or backup software\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects known sensitive file extensions\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = ((EventID="5145") (RelativeTargetName="*.pst" OR RelativeTargetName="*.ost" OR RelativeTargetName="*.msg" OR RelativeTargetName="*.nst" OR RelativeTargetName="*.oab" OR RelativeTargetName="*.edb" OR RelativeTargetName="*.nsf" OR RelativeTargetName="*.bak" OR RelativeTargetName="*.dmp" OR RelativeTargetName="*.kirbi" OR RelativeTargetName="*\\\\ntds.dit" OR RelativeTargetName="*\\\\groups.xml" OR RelativeTargetName="*.rdp")) | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_access_to_sensitive_file_extensions_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.collection,level=high"\n\n\n'
```
