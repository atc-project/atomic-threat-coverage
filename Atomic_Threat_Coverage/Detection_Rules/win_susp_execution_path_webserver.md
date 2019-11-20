| Title                | Execution in Webserver Root Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious program execution in a web service root folder (filter out false positives)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Various applications</li><li>Tools that include ping or nslookup command invocations</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Execution in Webserver Root Folder
id: 35efb964-e6a5-47ad-bbcd-19661854018d
status: experimental
description: Detects a suspicious program execution in a web service root folder (filter out false positives)
author: Florian Roth
tags:
    - attack.persistence
    - attack.t1100
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\wwwroot\\*'
            - '*\wmpub\\*'
            - '*\htdocs\\*'
    filter:
        Image:
            - '*bin\\*'
            - '*\Tools\\*'
            - '*\SMSComponent\\*'
        ParentImage:
            - '*\services.exe'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Various applications
    - Tools that include ping or nslookup command invocations
level: medium

```





### splunk
    
```
((Image="*\\\\wwwroot\\\\*" OR Image="*\\\\wmpub\\\\*" OR Image="*\\\\htdocs\\\\*") NOT ((Image="*bin\\\\*" OR Image="*\\\\Tools\\\\*" OR Image="*\\\\SMSComponent\\\\*") (ParentImage="*\\\\services.exe"))) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Execution in Webserver Root Folder]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Execution in Webserver Root Folder status: experimental \
description: Detects a suspicious program execution in a web service root folder (filter out false positives) \
references:  \
tags: ['attack.persistence', 'attack.t1100'] \
author: Florian Roth \
date:  \
falsepositives: ['Various applications', 'Tools that include ping or nslookup command invocations'] \
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
description = Detects a suspicious program execution in a web service root folder (filter out false positives)
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\wwwroot\\*" OR Image="*\\wmpub\\*" OR Image="*\\htdocs\\*") NOT ((Image="*bin\\*" OR Image="*\\Tools\\*" OR Image="*\\SMSComponent\\*") (ParentImage="*\\services.exe"))) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Execution_in_Webserver_Root_Folder_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.t1100,level=medium"
```
