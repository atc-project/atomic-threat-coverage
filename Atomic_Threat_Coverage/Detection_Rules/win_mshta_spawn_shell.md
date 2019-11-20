| Title                | MSHTA Spawning Windows Shell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Windows command line executable started from MSHTA.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1170: Mshta](../Triggers/T1170.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Printer software / driver installations</li><li>HP software</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.trustedsec.com/july-2015/malicious-htas/](https://www.trustedsec.com/july-2015/malicious-htas/)</li></ul>  |
| Author               | Michael Haag |
| Other Tags           | <ul><li>car.2013-02-003</li><li>car.2013-02-003</li><li>car.2013-03-001</li><li>car.2013-03-001</li><li>car.2014-04-003</li><li>car.2014-04-003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: MSHTA Spawning Windows Shell
id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
status: experimental
description: Detects a Windows command line executable started from MSHTA.
references:
    - https://www.trustedsec.com/july-2015/malicious-htas/
author: Michael Haag
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\mshta.exe'
        Image:
            - '*\cmd.exe'
            - '*\powershell.exe'
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\reg.exe'
            - '*\regsvr32.exe'
            - '*\BITSADMIN*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1170
    - car.2013-02-003
    - car.2013-03-001
    - car.2014-04-003
falsepositives:
    - Printer software / driver installations
    - HP software
level: high

```





### splunk
    
```
(ParentImage="*\\\\mshta.exe" (Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\sh.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\reg.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\BITSADMIN*")) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[MSHTA Spawning Windows Shell]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: MSHTA Spawning Windows Shell status: experimental \
description: Detects a Windows command line executable started from MSHTA. \
references: ['https://www.trustedsec.com/july-2015/malicious-htas/'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1170', 'car.2013-02-003', 'car.2013-03-001', 'car.2014-04-003'] \
author: Michael Haag \
date:  \
falsepositives: ['Printer software / driver installations', 'HP software'] \
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
description = Detects a Windows command line executable started from MSHTA.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (ParentImage="*\\mshta.exe" (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\reg.exe" OR Image="*\\regsvr32.exe" OR Image="*\\BITSADMIN*")) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup MSHTA_Spawning_Windows_Shell_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1170,sigma_tag=car.2013-02-003,sigma_tag=car.2013-03-001,sigma_tag=car.2014-04-003,level=high"
```
