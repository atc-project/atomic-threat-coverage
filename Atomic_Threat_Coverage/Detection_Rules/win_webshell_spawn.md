| Title                | Shells Spawned by Web Servers                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Particular web applications may spawn a shell process legitimately</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: Shells Spawned by Web Servers
id: 8202070f-edeb-4d31-a010-a26c72ac5600
status: experimental
description: Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack
author: Thomas Patzke
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\w3wp.exe'
            - '*\httpd.exe'
            - '*\nginx.exe'
            - '*\php-cgi.exe'
        Image:
            - '*\cmd.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\powershell.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1100
falsepositives:
    - Particular web applications may spawn a shell process legitimately
level: high

```





### splunk
    
```
((ParentImage="*\\\\w3wp.exe" OR ParentImage="*\\\\httpd.exe" OR ParentImage="*\\\\nginx.exe" OR ParentImage="*\\\\php-cgi.exe") (Image="*\\\\cmd.exe" OR Image="*\\\\sh.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\powershell.exe")) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Shells Spawned by Web Servers]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Shells Spawned by Web Servers status: experimental \
description: Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack \
references:  \
tags: ['attack.privilege_escalation', 'attack.persistence', 'attack.t1100'] \
author: Thomas Patzke \
date:  \
falsepositives: ['Particular web applications may spawn a shell process legitimately'] \
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
description = Web servers that spawn shell processes could be the result of a successfully placed web shell or an other attack
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((ParentImage="*\\w3wp.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\php-cgi.exe") (Image="*\\cmd.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\powershell.exe")) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Shells_Spawned_by_Web_Servers_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.privilege_escalation,sigma_tag=attack.persistence,sigma_tag=attack.t1100,level=high"
```
