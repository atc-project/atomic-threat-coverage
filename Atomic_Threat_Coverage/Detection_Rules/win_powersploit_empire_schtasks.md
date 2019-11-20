| Title                | Default PowerSploit and Empire Schtasks Persistence                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of a schtask via PowerSploit or Empire Default Configuration.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>False positives are possible, depends on organisation and processes</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1](https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1)</li><li>[https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/schtasks.py](https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/schtasks.py)</li><li>[https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/elevated/schtasks.py](https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/elevated/schtasks.py)</li></ul>  |
| Author               | Markus Neis, @Karneades |
| Other Tags           | <ul><li>attack.s0111</li><li>attack.s0111</li><li>attack.g0022</li><li>attack.g0022</li><li>attack.g0060</li><li>attack.g0060</li><li>car.2013-08-001</li><li>car.2013-08-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Default PowerSploit and Empire Schtasks Persistence
id: 56c217c3-2de2-479b-990f-5c109ba8458f
status: experimental
description: Detects the creation of a schtask via PowerSploit or Empire Default Configuration.
references:
    - https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1
    - https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/schtasks.py
    - https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/elevated/schtasks.py
author: Markus Neis, @Karneades
date: 2018/03/06
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage:
            - '*\powershell.exe'
        CommandLine:
            - '*schtasks*/Create*/SC *ONLOGON*/TN *Updater*/TR *powershell*'
            - '*schtasks*/Create*/SC *DAILY*/TN *Updater*/TR *powershell*'
            - '*schtasks*/Create*/SC *ONIDLE*/TN *Updater*/TR *powershell*'
            - '*schtasks*/Create*/SC *Updater*/TN *Updater*/TR *powershell*'
    condition: selection
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1053
    - attack.t1086
    - attack.s0111
    - attack.g0022
    - attack.g0060
    - car.2013-08-001
falsepositives:
    - False positives are possible, depends on organisation and processes
level: high

```





### splunk
    
```
((ParentImage="*\\\\powershell.exe") (CommandLine="*schtasks*/Create*/SC *ONLOGON*/TN *Updater*/TR *powershell*" OR CommandLine="*schtasks*/Create*/SC *DAILY*/TN *Updater*/TR *powershell*" OR CommandLine="*schtasks*/Create*/SC *ONIDLE*/TN *Updater*/TR *powershell*" OR CommandLine="*schtasks*/Create*/SC *Updater*/TN *Updater*/TR *powershell*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Default PowerSploit and Empire Schtasks Persistence]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Default PowerSploit and Empire Schtasks Persistence status: experimental \
description: Detects the creation of a schtask via PowerSploit or Empire Default Configuration. \
references: ['https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1', 'https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/schtasks.py', 'https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/elevated/schtasks.py'] \
tags: ['attack.execution', 'attack.persistence', 'attack.privilege_escalation', 'attack.t1053', 'attack.t1086', 'attack.s0111', 'attack.g0022', 'attack.g0060', 'car.2013-08-001'] \
author: Markus Neis, @Karneades \
date:  \
falsepositives: ['False positives are possible, depends on organisation and processes'] \
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
description = Detects the creation of a schtask via PowerSploit or Empire Default Configuration.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((ParentImage="*\\powershell.exe") (CommandLine="*schtasks*/Create*/SC *ONLOGON*/TN *Updater*/TR *powershell*" OR CommandLine="*schtasks*/Create*/SC *DAILY*/TN *Updater*/TR *powershell*" OR CommandLine="*schtasks*/Create*/SC *ONIDLE*/TN *Updater*/TR *powershell*" OR CommandLine="*schtasks*/Create*/SC *Updater*/TN *Updater*/TR *powershell*")) | stats values(*) AS * by _time | search NOT [| inputlookup Default_PowerSploit_and_Empire_Schtasks_Persistence_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.persistence,sigma_tag=attack.privilege_escalation,sigma_tag=attack.t1053,sigma_tag=attack.t1086,sigma_tag=attack.s0111,sigma_tag=attack.g0022,sigma_tag=attack.g0060,sigma_tag=car.2013-08-001,level=high"
```
