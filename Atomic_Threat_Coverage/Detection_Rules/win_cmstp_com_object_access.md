| Title                | CMSTP UAC Bypass via COM Object Access                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li><li>[T1191: CMSTP](https://attack.mitre.org/techniques/T1191)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1088: Bypass User Account Control](../Triggers/T1088.md)</li><li>[T1191: CMSTP](../Triggers/T1191.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Legitimate CMSTP use (unlikely in modern enterprise environments)</li></ul>  |
| Development Status   | stable |
| References           | <ul><li>[http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/](http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/)</li><li>[https://twitter.com/hFireF0X/status/897640081053364225](https://twitter.com/hFireF0X/status/897640081053364225)</li></ul>  |
| Author               | Nik Seetharaman |
| Other Tags           | <ul><li>attack.g0069</li><li>attack.g0069</li><li>car.2019-04-001</li><li>car.2019-04-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: CMSTP UAC Bypass via COM Object Access
id: 4b60e6f2-bf39-47b4-b4ea-398e33cfe253
status: stable
description: Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.execution
    - attack.t1088
    - attack.t1191
    - attack.g0069
    - car.2019-04-001
author: Nik Seetharaman
modified: 2019/07/31
references:
    - http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
    - https://twitter.com/hFireF0X/status/897640081053364225
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        ParentCommandLine: '*\DllHost.exe'
    selection2:
        ParentCommandLine:
            - '*{3E5FC7F9-9A51-4367-9063-A120244FBEC7}'
            - '*{3E000D72-A845-4CD9-BD83-80C07C3B881F}'
    condition: selection1 and selection2
fields:
    - CommandLine
    - ParentCommandLine
    - Hashes
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high

```





### splunk
    
```
(ParentCommandLine="*\\\\DllHost.exe" (ParentCommandLine="*{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" OR ParentCommandLine="*{3E000D72-A845-4CD9-BD83-80C07C3B881F}")) | table CommandLine,ParentCommandLine,Hashes
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[CMSTP UAC Bypass via COM Object Access]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$ \
Hashes: $result.Hashes$  \
title: CMSTP UAC Bypass via COM Object Access status: stable \
description: Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects \
references: ['http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/', 'https://twitter.com/hFireF0X/status/897640081053364225'] \
tags: ['attack.defense_evasion', 'attack.privilege_escalation', 'attack.execution', 'attack.t1088', 'attack.t1191', 'attack.g0069', 'car.2019-04-001'] \
author: Nik Seetharaman \
date:  \
falsepositives: ['Legitimate CMSTP use (unlikely in modern enterprise environments)'] \
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
description = Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (ParentCommandLine="*\\DllHost.exe" (ParentCommandLine="*{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" OR ParentCommandLine="*{3E000D72-A845-4CD9-BD83-80C07C3B881F}")) | table CommandLine,ParentCommandLine,Hashes,host | search NOT [| inputlookup CMSTP_UAC_Bypass_via_COM_Object_Access_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.privilege_escalation,sigma_tag=attack.execution,sigma_tag=attack.t1088,sigma_tag=attack.t1191,sigma_tag=attack.g0069,sigma_tag=car.2019-04-001,level=high"
```
