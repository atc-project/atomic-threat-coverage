| Title                | Suspicious Rundll32 Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious process related to rundll32 based on arguments                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1085: Rundll32](../Triggers/T1085.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://www.hexacorn.com/blog/2017/05/01/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline/](http://www.hexacorn.com/blog/2017/05/01/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline/)</li><li>[https://twitter.com/Hexacorn/status/885258886428725250](https://twitter.com/Hexacorn/status/885258886428725250)</li><li>[https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52](https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52)</li></ul>  |
| Author               | juju4 |


## Detection Rules

### Sigma rule

```
title: Suspicious Rundll32 Activity
id: e593cf51-88db-4ee1-b920-37e89012a3c9
description: Detects suspicious process related to rundll32 based on arguments
status: experimental
references:
    - http://www.hexacorn.com/blog/2017/05/01/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline/
    - https://twitter.com/Hexacorn/status/885258886428725250
    - https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1085
author: juju4
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\rundll32.exe* url.dll,*OpenURL *'
            - '*\rundll32.exe* url.dll,*OpenURLA *'
            - '*\rundll32.exe* url.dll,*FileProtocolHandler *'
            - '*\rundll32.exe* zipfldr.dll,*RouteTheCall *'
            - '*\rundll32.exe* Shell32.dll,*Control_RunDLL *'
            - '*\rundll32.exe javascript:*'
            - '* url.dll,*OpenURL *'
            - '* url.dll,*OpenURLA *'
            - '* url.dll,*FileProtocolHandler *'
            - '* zipfldr.dll,*RouteTheCall *'
            - '* Shell32.dll,*Control_RunDLL *'
            - '* javascript:*'
            - '*.RegisterXLL*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### splunk
    
```
(CommandLine="*\\\\rundll32.exe* url.dll,*OpenURL *" OR CommandLine="*\\\\rundll32.exe* url.dll,*OpenURLA *" OR CommandLine="*\\\\rundll32.exe* url.dll,*FileProtocolHandler *" OR CommandLine="*\\\\rundll32.exe* zipfldr.dll,*RouteTheCall *" OR CommandLine="*\\\\rundll32.exe* Shell32.dll,*Control_RunDLL *" OR CommandLine="*\\\\rundll32.exe javascript:*" OR CommandLine="* url.dll,*OpenURL *" OR CommandLine="* url.dll,*OpenURLA *" OR CommandLine="* url.dll,*FileProtocolHandler *" OR CommandLine="* zipfldr.dll,*RouteTheCall *" OR CommandLine="* Shell32.dll,*Control_RunDLL *" OR CommandLine="* javascript:*" OR CommandLine="*.RegisterXLL*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious Rundll32 Activity]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious Rundll32 Activity status: experimental \
description: Detects suspicious process related to rundll32 based on arguments \
references: ['http://www.hexacorn.com/blog/2017/05/01/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline/', 'https://twitter.com/Hexacorn/status/885258886428725250', 'https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1085'] \
author: juju4 \
date:  \
falsepositives: ['False positives depend on scripts and administrative tools used in the monitored environment'] \
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
description = Detects suspicious process related to rundll32 based on arguments
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="*\\rundll32.exe* url.dll,*OpenURL *" OR CommandLine="*\\rundll32.exe* url.dll,*OpenURLA *" OR CommandLine="*\\rundll32.exe* url.dll,*FileProtocolHandler *" OR CommandLine="*\\rundll32.exe* zipfldr.dll,*RouteTheCall *" OR CommandLine="*\\rundll32.exe* Shell32.dll,*Control_RunDLL *" OR CommandLine="*\\rundll32.exe javascript:*" OR CommandLine="* url.dll,*OpenURL *" OR CommandLine="* url.dll,*OpenURLA *" OR CommandLine="* url.dll,*FileProtocolHandler *" OR CommandLine="* zipfldr.dll,*RouteTheCall *" OR CommandLine="* Shell32.dll,*Control_RunDLL *" OR CommandLine="* javascript:*" OR CommandLine="*.RegisterXLL*") | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_Rundll32_Activity_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1085,level=medium"
```
