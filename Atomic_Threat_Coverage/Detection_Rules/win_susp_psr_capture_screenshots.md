| Title                | psr.exe capture screenshots                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | The psr.exe captures desktop screenshots and saves them on the local machine                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Psr.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Psr.yml)</li><li>[https://www.sans.org/summit-archives/file/summit-archive-1493861893.pdf](https://www.sans.org/summit-archives/file/summit-archive-1493861893.pdf)</li></ul>  |
| Author               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: psr.exe capture screenshots
id: 2158f96f-43c2-43cb-952a-ab4580f32382
status: experimental
description: The psr.exe captures desktop screenshots and saves them on the local machine
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Psr.yml
    - https://www.sans.org/summit-archives/file/summit-archive-1493861893.pdf
author: Beyu Denis, oscd.community
date: 2019/10/12
modified: 2019/11/04
tags:
    - attack.persistence
    - attack.t1218
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Psr.exe'
        CommandLine|contains: '/start'
    condition: selection 
falsepositives:
    - Unknown

```





### splunk
    
```
(Image="*\\\\Psr.exe" CommandLine="*/start*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[psr.exe capture screenshots]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: psr.exe capture screenshots status: experimental \
description: The psr.exe captures desktop screenshots and saves them on the local machine \
references: ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Psr.yml', 'https://www.sans.org/summit-archives/file/summit-archive-1493861893.pdf'] \
tags: ['attack.persistence', 'attack.t1218'] \
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
description = The psr.exe captures desktop screenshots and saves them on the local machine
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\Psr.exe" CommandLine="*/start*") | stats values(*) AS * by _time | search NOT [| inputlookup psr.exe_capture_screenshots_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.t1218,level=medium"
```
