| Title                | Mustang Panda Dropper                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects specific process parameters as used by Mustang Panda droppers                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://app.any.run/tasks/7ca5661d-a67b-43ec-98c1-dd7a8103c256/](https://app.any.run/tasks/7ca5661d-a67b-43ec-98c1-dd7a8103c256/)</li><li>[https://app.any.run/tasks/b12cccf3-1c22-4e28-9d3e-c7a6062f3914/](https://app.any.run/tasks/b12cccf3-1c22-4e28-9d3e-c7a6062f3914/)</li><li>[https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations](https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Mustang Panda Dropper
id: 2d87d610-d760-45ee-a7e6-7a6f2a65de00
status: experimental
description: Detects specific process parameters as used by Mustang Panda droppers
author: Florian Roth
date: 2019/10/30
references:
    - https://app.any.run/tasks/7ca5661d-a67b-43ec-98c1-dd7a8103c256/
    - https://app.any.run/tasks/b12cccf3-1c22-4e28-9d3e-c7a6062f3914/
    - https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine: 
            - '*Temp\wtask.exe /create*'
            - '*%windir:~-3,1%%PUBLIC:~-9,1%*'
            - '*/E:vbscript * C:\Users\*.txt" /F'
            - '*/tn "Security Script *'
            - '*%windir:~-1,1%*'
    selection2:
        Image:
            - '*Temp\winwsh.exe'
    condition: 1 of them
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unlikely
level: high

```





### splunk
    
```
((CommandLine="*Temp\\\\wtask.exe /create*" OR CommandLine="*%windir:~-3,1%%PUBLIC:~-9,1%*" OR CommandLine="*/E:vbscript * C:\\\\Users\\*.txt\\" /F" OR CommandLine="*/tn \\"Security Script *" OR CommandLine="*%windir:~-1,1%*") OR (Image="*Temp\\\\winwsh.exe")) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Mustang Panda Dropper]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Mustang Panda Dropper status: experimental \
description: Detects specific process parameters as used by Mustang Panda droppers \
references: ['https://app.any.run/tasks/7ca5661d-a67b-43ec-98c1-dd7a8103c256/', 'https://app.any.run/tasks/b12cccf3-1c22-4e28-9d3e-c7a6062f3914/', 'https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations'] \
tags:  \
author: Florian Roth \
date:  \
falsepositives: ['Unlikely'] \
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
description = Detects specific process parameters as used by Mustang Panda droppers
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((CommandLine="*Temp\\wtask.exe /create*" OR CommandLine="*%windir:~-3,1%%PUBLIC:~-9,1%*" OR CommandLine="*/E:vbscript * C:\\Users\*.txt\" /F" OR CommandLine="*/tn \"Security Script *" OR CommandLine="*%windir:~-1,1%*") OR (Image="*Temp\\winwsh.exe")) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Mustang_Panda_Dropper_whitelist.csv]
```
