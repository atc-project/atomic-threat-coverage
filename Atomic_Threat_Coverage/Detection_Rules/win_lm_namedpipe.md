| Title                | First time seen remote named pipe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li></ul>  |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1077: Windows Admin Shares](../Triggers/T1077.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>update the excluded named pipe to filter out any newly observed legit named pipe</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://twitter.com/menasec1/status/1104489274387451904](https://twitter.com/menasec1/status/1104489274387451904)</li></ul>  |
| Author               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: First time seen remote named pipe
id: 52d8b0c6-53d6-439a-9e41-52ad442ad9ad
description: This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec
    using named pipes
author: Samir Bousseaden
references:
    - https://twitter.com/menasec1/status/1104489274387451904
tags:
    - attack.lateral_movement
    - attack.t1077
logsource:
    product: windows
    service: security
    description: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection1:
        EventID: 5145
        ShareName: \\*\IPC$
    selection2:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName:
         - 'atsvc'
         - 'samr'
         - 'lsarpc'
         - 'winreg'
         - 'netlogon'
         - 'srvsvc'
         - 'protected_storage'
         - 'wkssvc'
         - 'browser'
         - 'netdfs'
    condition: selection1 and not selection2
falsepositives: 
    - update the excluded named pipe to filter out any newly observed legit named pipe
level: high

```





### splunk
    
```
((EventID="5145" ShareName="\\\\*\\\\IPC$") NOT (EventID="5145" ShareName="\\\\*\\\\IPC$" (RelativeTargetName="atsvc" OR RelativeTargetName="samr" OR RelativeTargetName="lsarpc" OR RelativeTargetName="winreg" OR RelativeTargetName="netlogon" OR RelativeTargetName="srvsvc" OR RelativeTargetName="protected_storage" OR RelativeTargetName="wkssvc" OR RelativeTargetName="browser" OR RelativeTargetName="netdfs")))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[First time seen remote named pipe]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: First time seen remote named pipe status:  \\\ndescription: This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes \\\nreferences: [\'https://twitter.com/menasec1/status/1104489274387451904\'] \\\ntags: [\'attack.lateral_movement\', \'attack.t1077\'] \\\nauthor: Samir Bousseaden \\\ndate:  \\\nfalsepositives: [\'update the excluded named pipe to filter out any newly observed legit named pipe\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = ((EventID="5145" ShareName="\\\\*\\\\IPC$") NOT (EventID="5145" ShareName="\\\\*\\\\IPC$" (RelativeTargetName="atsvc" OR RelativeTargetName="samr" OR RelativeTargetName="lsarpc" OR RelativeTargetName="winreg" OR RelativeTargetName="netlogon" OR RelativeTargetName="srvsvc" OR RelativeTargetName="protected_storage" OR RelativeTargetName="wkssvc" OR RelativeTargetName="browser" OR RelativeTargetName="netdfs"))) | stats values(*) AS * by _time | search NOT [| inputlookup First_time_seen_remote_named_pipe_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1077,level=high"\n\n\n'
```
