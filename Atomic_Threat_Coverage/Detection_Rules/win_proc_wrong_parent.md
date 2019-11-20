| Title                | Windows Processes Suspicious Parent Directory                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detect suspicious parent processes of well-known Windows processes                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Some security products seem to spawn these</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2](https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2)</li><li>[https://www.carbonblack.com/2014/06/10/screenshot-demo-hunt-evil-faster-than-ever-with-carbon-black/](https://www.carbonblack.com/2014/06/10/screenshot-demo-hunt-evil-faster-than-ever-with-carbon-black/)</li><li>[https://www.13cubed.com/downloads/windows_process_genealogy_v2.pdf](https://www.13cubed.com/downloads/windows_process_genealogy_v2.pdf)</li><li>[https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)</li></ul>  |
| Author               | vburov |


## Detection Rules

### Sigma rule

```
title: Windows Processes Suspicious Parent Directory
id: 96036718-71cc-4027-a538-d1587e0006a7
status: experimental
description: Detect suspicious parent processes of well-known Windows processes
author: vburov
references:
    - https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2
    - https://www.carbonblack.com/2014/06/10/screenshot-demo-hunt-evil-faster-than-ever-with-carbon-black/
    - https://www.13cubed.com/downloads/windows_process_genealogy_v2.pdf
    - https://attack.mitre.org/techniques/T1036/
date: 2019/02/23
modified: 2019/08/20
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
            - '*\taskhost.exe'
            - '*\lsm.exe'
            - '*\lsass.exe'
            - '*\services.exe'
            - '*\lsaiso.exe'
            - '*\csrss.exe'
            - '*\wininit.exe'
            - '*\winlogon.exe'
    filter:
        ParentImage:
            - '*\System32\\*'
            - '*\SysWOW64\\*'
            - '*\SavService.exe'
            - '*\Windows Defender\\*\MsMpEng.exe'
    filter_null:
        ParentImage: null
    condition: selection and not filter and not filter_null
falsepositives:
    - Some security products seem to spawn these
level: low

```





### splunk
    
```
(((Image="*\\\\svchost.exe" OR Image="*\\\\taskhost.exe" OR Image="*\\\\lsm.exe" OR Image="*\\\\lsass.exe" OR Image="*\\\\services.exe" OR Image="*\\\\lsaiso.exe" OR Image="*\\\\csrss.exe" OR Image="*\\\\wininit.exe" OR Image="*\\\\winlogon.exe") NOT ((ParentImage="*\\\\System32\\\\*" OR ParentImage="*\\\\SysWOW64\\\\*" OR ParentImage="*\\\\SavService.exe" OR ParentImage="*\\\\Windows Defender\\\\*\\\\MsMpEng.exe"))) NOT (NOT ParentImage="*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Windows Processes Suspicious Parent Directory]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Windows Processes Suspicious Parent Directory status: experimental \
description: Detect suspicious parent processes of well-known Windows processes \
references: ['https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2', 'https://www.carbonblack.com/2014/06/10/screenshot-demo-hunt-evil-faster-than-ever-with-carbon-black/', 'https://www.13cubed.com/downloads/windows_process_genealogy_v2.pdf', 'https://attack.mitre.org/techniques/T1036/'] \
tags: ['attack.defense_evasion', 'attack.t1036'] \
author: vburov \
date:  \
falsepositives: ['Some security products seem to spawn these'] \
level: low
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detect suspicious parent processes of well-known Windows processes
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (((Image="*\\svchost.exe" OR Image="*\\taskhost.exe" OR Image="*\\lsm.exe" OR Image="*\\lsass.exe" OR Image="*\\services.exe" OR Image="*\\lsaiso.exe" OR Image="*\\csrss.exe" OR Image="*\\wininit.exe" OR Image="*\\winlogon.exe") NOT ((ParentImage="*\\System32\\*" OR ParentImage="*\\SysWOW64\\*" OR ParentImage="*\\SavService.exe" OR ParentImage="*\\Windows Defender\\*\\MsMpEng.exe"))) NOT (NOT ParentImage="*")) | stats values(*) AS * by _time | search NOT [| inputlookup Windows_Processes_Suspicious_Parent_Directory_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1036,level=low"
```
