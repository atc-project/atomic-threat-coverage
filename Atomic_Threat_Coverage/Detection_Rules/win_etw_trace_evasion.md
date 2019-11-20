| Title                | Disable of ETW Trace                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a command that clears or disables any ETW trace log which could indicate a logging evasion.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li></ul>  |
| Severity Level       | high |
| False Positives      |  There are no documented False Positives for this Detection Rule yet  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)</li><li>[https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_mal_lockergoga.yml](https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_mal_lockergoga.yml)</li><li>[https://abuse.io/lockergoga.txt](https://abuse.io/lockergoga.txt)</li></ul>  |
| Author               | @neu5ron, Florian Roth |
| Other Tags           | <ul><li>car.2016-04-002</li><li>car.2016-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Disable of ETW Trace
id: a238b5d0-ce2d-4414-a676-7a531b3d13d6
description: Detects a command that clears or disables any ETW trace log which could indicate a logging evasion.
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
    - https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_mal_lockergoga.yml
    - https://abuse.io/lockergoga.txt
author: '@neu5ron, Florian Roth'
date: 2019/03/22
tags:
    - attack.execution
    - attack.t1070  
    - car.2016-04-002  
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection_clear_1:
        CommandLine: '* cl */Trace*'
    selection_clear_2:
        CommandLine: '* clear-log */Trace*'
    selection_disable_1:
        CommandLine: '* sl* /e:false*'
    selection_disable_2:
        CommandLine: '* set-log* /e:false*'
    condition: selection_clear_1 or selection_clear_2 or selection_disable_1 or selection_disable_2

```





### splunk
    
```
(CommandLine="* cl */Trace*" OR CommandLine="* clear-log */Trace*" OR CommandLine="* sl* /e:false*" OR CommandLine="* set-log* /e:false*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Disable of ETW Trace]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Disable of ETW Trace status:  \
description: Detects a command that clears or disables any ETW trace log which could indicate a logging evasion. \
references: ['https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil', 'https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_mal_lockergoga.yml', 'https://abuse.io/lockergoga.txt'] \
tags: ['attack.execution', 'attack.t1070', 'car.2016-04-002'] \
author: @neu5ron, Florian Roth \
date:  \
falsepositives:  \
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
description = Detects a command that clears or disables any ETW trace log which could indicate a logging evasion.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="* cl */Trace*" OR CommandLine="* clear-log */Trace*" OR CommandLine="* sl* /e:false*" OR CommandLine="* set-log* /e:false*") | stats values(*) AS * by _time | search NOT [| inputlookup Disable_of_ETW_Trace_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1070,sigma_tag=car.2016-04-002,level=high"
```
