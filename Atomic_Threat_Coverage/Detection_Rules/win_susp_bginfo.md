| Title                | Application whitelisting bypass via bginfo                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Execute VBscript code that is referenced within the *.bgi file.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Bginfo.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Bginfo.yml)</li><li>[https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/](https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/)</li></ul>  |
| Author               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Application whitelisting bypass via bginfo
id: aaf46cdc-934e-4284-b329-34aa701e3771
status: experimental
description: Execute VBscript code that is referenced within the *.bgi file.
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Bginfo.yml
    - https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/
author: Beyu Denis, oscd.community
date: 2019/10/26
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: medium
logsource:
    category: process_creation
    product: windows
detection:
  selection:
    Image|endswith: '\bginfo.exe'
    CommandLine|contains|all:
        - '/popup'
        - '/nolicprompt'
  condition: selection
falsepositives:
    - Unknown

```





### splunk
    
```
(Image="*\\\\bginfo.exe" CommandLine="*/popup*" CommandLine="*/nolicprompt*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Application whitelisting bypass via bginfo]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Application whitelisting bypass via bginfo status: experimental \
description: Execute VBscript code that is referenced within the *.bgi file. \
references: ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Bginfo.yml', 'https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1218'] \
author: Beyu Denis, oscd.community \
date:  \
falsepositives: ['Unknown'] \
level: medium
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Execute VBscript code that is referenced within the *.bgi file.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\bginfo.exe" CommandLine="*/popup*" CommandLine="*/nolicprompt*") | stats values(*) AS * by _time | search NOT [| inputlookup Application_whitelisting_bypass_via_bginfo_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1218,level=medium"
```
