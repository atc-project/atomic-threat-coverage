| Title                | MMC Spawning Windows Shell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Windows command line executable started from MMC.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1175: Distributed Component Object Model](https://attack.mitre.org/techniques/T1175)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1175: Distributed Component Object Model](../Triggers/T1175.md)</li></ul>  |
| Severity Level       | high |
| False Positives      |  There are no documented False Positives for this Detection Rule yet  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Karneades, Swisscom CSIRT |


## Detection Rules

### Sigma rule

```
title: MMC Spawning Windows Shell
id: 05a2ab7e-ce11-4b63-86db-ab32e763e11d
status: experimental
description: Detects a Windows command line executable started from MMC.
author: Karneades, Swisscom CSIRT
tags:
    - attack.lateral_movement
    - attack.t1175
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\mmc.exe'
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
    - Image
    - ParentCommandLine
level: high

```





### splunk
    
```
(ParentImage="*\\\\mmc.exe" (Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\sh.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\reg.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\BITSADMIN*")) | table CommandLine,Image,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[MMC Spawning Windows Shell]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
Image: $result.Image$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: MMC Spawning Windows Shell status: experimental \
description: Detects a Windows command line executable started from MMC. \
references:  \
tags: ['attack.lateral_movement', 'attack.t1175'] \
author: Karneades, Swisscom CSIRT \
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
description = Detects a Windows command line executable started from MMC.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (ParentImage="*\\mmc.exe" (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\reg.exe" OR Image="*\\regsvr32.exe" OR Image="*\\BITSADMIN*")) | table CommandLine,Image,ParentCommandLine,host | search NOT [| inputlookup MMC_Spawning_Windows_Shell_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1175,level=high"
```
