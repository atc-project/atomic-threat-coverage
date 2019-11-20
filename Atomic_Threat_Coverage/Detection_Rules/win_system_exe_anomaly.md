| Title                | System File Execution Location Anomaly                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Windows program executable started in a suspicious folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Exotic software</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/GelosSnake/status/934900723426439170](https://twitter.com/GelosSnake/status/934900723426439170)</li></ul>  |
| Author               | Florian Roth, Patrick Bareiss |


## Detection Rules

### Sigma rule

```
title: System File Execution Location Anomaly
id: e4a6b256-3e47-40fc-89d2-7a477edd6915
status: experimental
description: Detects a Windows program executable started in a suspicious folder
references:
    - https://twitter.com/GelosSnake/status/934900723426439170
author: Florian Roth, Patrick Bareiss
date: 2017/11/27
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\svchost.exe'
            - '*\rundll32.exe'
            - '*\services.exe'
            - '*\powershell.exe'
            - '*\regsvr32.exe'
            - '*\spoolsv.exe'
            - '*\lsass.exe'
            - '*\smss.exe'
            - '*\csrss.exe'
            - '*\conhost.exe'
            - '*\wininit.exe'
            - '*\lsm.exe'
            - '*\winlogon.exe'
            - '*\explorer.exe'
            - '*\taskhost.exe' 
    filter:
        Image:
            - 'C:\Windows\System32\\*'
            - 'C:\Windows\SysWow64\\*'
            - 'C:\Windows\explorer.exe'
            - 'C:\Windows\winsxs\\*'
    condition: selection and not filter
falsepositives:
    - Exotic software
level: high

```





### splunk
    
```
((Image="*\\\\svchost.exe" OR Image="*\\\\rundll32.exe" OR Image="*\\\\services.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\spoolsv.exe" OR Image="*\\\\lsass.exe" OR Image="*\\\\smss.exe" OR Image="*\\\\csrss.exe" OR Image="*\\\\conhost.exe" OR Image="*\\\\wininit.exe" OR Image="*\\\\lsm.exe" OR Image="*\\\\winlogon.exe" OR Image="*\\\\explorer.exe" OR Image="*\\\\taskhost.exe") NOT ((Image="C:\\\\Windows\\\\System32\\\\*" OR Image="C:\\\\Windows\\\\SysWow64\\\\*" OR Image="C:\\\\Windows\\\\explorer.exe" OR Image="C:\\\\Windows\\\\winsxs\\\\*")))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[System File Execution Location Anomaly]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: System File Execution Location Anomaly status: experimental \
description: Detects a Windows program executable started in a suspicious folder \
references: ['https://twitter.com/GelosSnake/status/934900723426439170'] \
tags: ['attack.defense_evasion', 'attack.t1036'] \
author: Florian Roth, Patrick Bareiss \
date:  \
falsepositives: ['Exotic software'] \
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
description = Detects a Windows program executable started in a suspicious folder
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\svchost.exe" OR Image="*\\rundll32.exe" OR Image="*\\services.exe" OR Image="*\\powershell.exe" OR Image="*\\regsvr32.exe" OR Image="*\\spoolsv.exe" OR Image="*\\lsass.exe" OR Image="*\\smss.exe" OR Image="*\\csrss.exe" OR Image="*\\conhost.exe" OR Image="*\\wininit.exe" OR Image="*\\lsm.exe" OR Image="*\\winlogon.exe" OR Image="*\\explorer.exe" OR Image="*\\taskhost.exe") NOT ((Image="C:\\Windows\\System32\\*" OR Image="C:\\Windows\\SysWow64\\*" OR Image="C:\\Windows\\explorer.exe" OR Image="C:\\Windows\\winsxs\\*"))) | stats values(*) AS * by _time | search NOT [| inputlookup System_File_Execution_Location_Anomaly_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1036,level=high"
```
