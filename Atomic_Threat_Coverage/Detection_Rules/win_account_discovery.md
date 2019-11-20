| Title                | AD Privileged Users or Groups Reconnaissance                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li></ul>  |
| Data Needed          | <ul><li>[DN_0029_4661_handle_to_an_object_was_requested](../Data_Needed/DN_0029_4661_handle_to_an_object_was_requested.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>if source account name is not an admin then its super suspicious</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html](https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html)</li></ul>  |
| Author               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: AD Privileged Users or Groups Reconnaissance
id: 35ba1d85-724d-42a3-889f-2e2362bcaf23
description: Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs
references:
    - https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html
tags:
    - attack.discovery
    - attack.t1087
status: experimental
author: Samir Bousseaden
logsource:
    product: windows
    service: security
    definition: 'Requirements: enable Object Access SAM on your Domain Controllers'
detection:
    selection:
        EventID: 4661
        ObjectType:
        - 'SAM_USER'
        - 'SAM_GROUP'
        ObjectName:
         - '*-512'
         - '*-502'
         - '*-500'
         - '*-505'
         - '*-519'
         - '*-520'
         - '*-544'
         - '*-551'
         - '*-555'
         - '*admin*'
    condition: selection
falsepositives:
    - if source account name is not an admin then its super suspicious
level: high

```





### splunk
    
```
(EventID="4661" (ObjectType="SAM_USER" OR ObjectType="SAM_GROUP") (ObjectName="*-512" OR ObjectName="*-502" OR ObjectName="*-500" OR ObjectName="*-505" OR ObjectName="*-519" OR ObjectName="*-520" OR ObjectName="*-544" OR ObjectName="*-551" OR ObjectName="*-555" OR ObjectName="*admin*"))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[AD Privileged Users or Groups Reconnaissance]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: AD Privileged Users or Groups Reconnaissance status: experimental \\\ndescription: Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs \\\nreferences: [\'https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html\'] \\\ntags: [\'attack.discovery\', \'attack.t1087\'] \\\nauthor: Samir Bousseaden \\\ndate:  \\\nfalsepositives: [\'if source account name is not an admin then its super suspicious\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="4661" (ObjectType="SAM_USER" OR ObjectType="SAM_GROUP") (ObjectName="*-512" OR ObjectName="*-502" OR ObjectName="*-500" OR ObjectName="*-505" OR ObjectName="*-519" OR ObjectName="*-520" OR ObjectName="*-544" OR ObjectName="*-551" OR ObjectName="*-555" OR ObjectName="*admin*")) | stats values(*) AS * by _time | search NOT [| inputlookup AD_Privileged_Users_or_Groups_Reconnaissance_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.discovery,sigma_tag=attack.t1087,level=high"\n\n\n'
```
