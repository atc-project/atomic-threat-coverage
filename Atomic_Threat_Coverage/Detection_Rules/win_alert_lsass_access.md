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
b'# Generated with Sigma2SplunkAlert\n[LSASS Access Detected via Attack Surface Reduction]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: LSASS Access Detected via Attack Surface Reduction status: experimental \\\ndescription: Detects Access to LSASS Process \\\nreferences: [\'https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard?WT.mc_id=twitter\'] \\\ntags: [\'attack.credential_access\', \'attack.t1003\'] \\\nauthor: Markus Neis \\\ndate:  \\\nfalsepositives: [\'Google Chrome GoogleUpdate.exe\', \'Some Taskmgr.exe related activity\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects Access to LSASS Process\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="1121" Path="*\\\\lsass.exe") | stats values(*) AS * by _time | search NOT [| inputlookup LSASS_Access_Detected_via_Attack_Surface_Reduction_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,level=high"\n\n\n'
```
