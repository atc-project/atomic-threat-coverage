| Title                | Microsoft Office Product Spawning Windows Shell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Windows command line executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1059: Command-Line Interface](https://attack.mitre.org/techniques/T1059)</li><li>[T1202: Indirect Command Execution](https://attack.mitre.org/techniques/T1202)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1059: Command-Line Interface](../Triggers/T1059.md)</li><li>[T1202: Indirect Command Execution](../Triggers/T1202.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100](https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100)</li><li>[https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html](https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html)</li></ul>  |
| Author               | Michael Haag, Florian Roth, Markus Neis |
| Other Tags           | <ul><li>car.2013-02-003</li><li>car.2013-02-003</li><li>car.2014-04-003</li><li>car.2014-04-003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Microsoft Office Product Spawning Windows Shell
id: 438025f9-5856-4663-83f7-52f878a70a50
status: experimental
description: Detects a Windows command line executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio.
references:
    - https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100
    - https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059
    - attack.t1202
    - car.2013-02-003
    - car.2014-04-003
author: Michael Haag, Florian Roth, Markus Neis
date: 2018/04/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\WINWORD.EXE'
            - '*\EXCEL.EXE'
            - '*\POWERPNT.exe'
            - '*\MSPUB.exe'
            - '*\VISIO.exe'
            - '*\OUTLOOK.EXE'
        Image:
            - '*\cmd.exe'
            - '*\powershell.exe'
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\scrcons.exe'
            - '*\schtasks.exe'
            - '*\regsvr32.exe'
            - '*\hh.exe'
            - '*\wmic.exe'  # https://app.any.run/tasks/c903e9c8-0350-440c-8688-3881b556b8e0/
            - '*\mshta.exe'
            - '*\rundll32.exe'
            - '*\msiexec.exe'
            - '*\forfiles.exe'
            - '*\scriptrunner.exe'
            - '*\mftrace.exe'
            - '*\AppVLP.exe'
            - '*\svchost.exe'  # https://www.vmray.com/analyses/2d2fa29185ad/report/overview.html
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high

```





### splunk
    
```
((ParentImage="*\\\\WINWORD.EXE" OR ParentImage="*\\\\EXCEL.EXE" OR ParentImage="*\\\\POWERPNT.exe" OR ParentImage="*\\\\MSPUB.exe" OR ParentImage="*\\\\VISIO.exe" OR ParentImage="*\\\\OUTLOOK.EXE") (Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\sh.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\scrcons.exe" OR Image="*\\\\schtasks.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\hh.exe" OR Image="*\\\\wmic.exe" OR Image="*\\\\mshta.exe" OR Image="*\\\\rundll32.exe" OR Image="*\\\\msiexec.exe" OR Image="*\\\\forfiles.exe" OR Image="*\\\\scriptrunner.exe" OR Image="*\\\\mftrace.exe" OR Image="*\\\\AppVLP.exe" OR Image="*\\\\svchost.exe")) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Microsoft Office Product Spawning Windows Shell]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Microsoft Office Product Spawning Windows Shell status: experimental \
description: Detects a Windows command line executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio. \
references: ['https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100', 'https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html'] \
tags: ['attack.execution', 'attack.defense_evasion', 'attack.t1059', 'attack.t1202', 'car.2013-02-003', 'car.2014-04-003'] \
author: Michael Haag, Florian Roth, Markus Neis \
date:  \
falsepositives: ['unknown'] \
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
description = Detects a Windows command line executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\POWERPNT.exe" OR ParentImage="*\\MSPUB.exe" OR ParentImage="*\\VISIO.exe" OR ParentImage="*\\OUTLOOK.EXE") (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\scrcons.exe" OR Image="*\\schtasks.exe" OR Image="*\\regsvr32.exe" OR Image="*\\hh.exe" OR Image="*\\wmic.exe" OR Image="*\\mshta.exe" OR Image="*\\rundll32.exe" OR Image="*\\msiexec.exe" OR Image="*\\forfiles.exe" OR Image="*\\scriptrunner.exe" OR Image="*\\mftrace.exe" OR Image="*\\AppVLP.exe" OR Image="*\\svchost.exe")) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Microsoft_Office_Product_Spawning_Windows_Shell_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.defense_evasion,sigma_tag=attack.t1059,sigma_tag=attack.t1202,sigma_tag=car.2013-02-003,sigma_tag=car.2014-04-003,level=high"
```
