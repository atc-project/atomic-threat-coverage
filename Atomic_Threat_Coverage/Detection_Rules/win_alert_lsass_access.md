| Title                | LSASS Access Detected via Attack Surface Reduction                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Access to LSASS Process                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Google Chrome GoogleUpdate.exe</li><li>Some Taskmgr.exe related activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard?WT.mc_id=twitter](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard?WT.mc_id=twitter)</li></ul>  |
| Author               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: LSASS Access Detected via Attack Surface Reduction
id: a0a278fe-2c0e-4de2-ac3c-c68b08a9ba98
description: Detects Access to LSASS Process
status: experimental
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard?WT.mc_id=twitter
author: Markus Neis
date: 2018/08/26
tags:
    - attack.credential_access
    - attack.t1003
# Defender Attack Surface Reduction
logsource:
    product: windows_defender
    definition: 'Requirements:Enabled Block credential stealing from the Windows local security authority subsystem (lsass.exe) from Attack Surface Reduction (GUID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2)'
detection:
    selection:
        EventID: 1121
        Path: '*\lsass.exe'
    condition: selection
falsepositives:
    - Google Chrome GoogleUpdate.exe
    - Some Taskmgr.exe related activity
level: high

```





### splunk
    
```
(EventID="1121" Path="*\\\\lsass.exe")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[LSASS Access Detected via Attack Surface Reduction]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: LSASS Access Detected via Attack Surface Reduction status: experimental \
description: Detects Access to LSASS Process \
references: ['https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard?WT.mc_id=twitter'] \
tags: ['attack.credential_access', 'attack.t1003'] \
author: Markus Neis \
date:  \
falsepositives: ['Google Chrome GoogleUpdate.exe', 'Some Taskmgr.exe related activity'] \
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
description = Detects Access to LSASS Process
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="1121" Path="*\\lsass.exe") | stats values(*) AS * by _time | search NOT [| inputlookup LSASS_Access_Detected_via_Attack_Surface_Reduction_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,level=high"
```
