| Title                | Microsoft Malware Protection Engine Crash                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This rule detects a suspicious crash of the Microsoft Malware Protection Engine                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li><li>[T1211: Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li><li>[T1211: Exploitation for Defense Evasion](../Triggers/T1211.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>MsMpEng.exe can crash when C:\ is full</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5](https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5)</li><li>[https://technet.microsoft.com/en-us/library/security/4022344](https://technet.microsoft.com/en-us/library/security/4022344)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Microsoft Malware Protection Engine Crash
id: 6c82cf5c-090d-4d57-9188-533577631108
description: This rule detects a suspicious crash of the Microsoft Malware Protection Engine
tags:
    - attack.defense_evasion
    - attack.t1089
    - attack.t1211
status: experimental
date: 2017/05/09
references:
    - https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5
    - https://technet.microsoft.com/en-us/library/security/4022344
author: Florian Roth
logsource:
    product: windows
    service: application
detection:
    selection1:
        Source: 'Application Error'
        EventID: 1000
    selection2:
        Source: 'Windows Error Reporting'
        EventID: 1001
    keywords:
        Message:
            - '*MsMpEng.exe*'
            - '*mpengine.dll*'
    condition: 1 of selection* and all of keywords
falsepositives:
    - MsMpEng.exe can crash when C:\ is full
level: high

```





### splunk
    
```
(((Source="Application Error" EventID="1000") OR (Source="Windows Error Reporting" EventID="1001")) (Message="*MsMpEng.exe*" OR Message="*mpengine.dll*"))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Microsoft Malware Protection Engine Crash]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Microsoft Malware Protection Engine Crash status: experimental \\\ndescription: This rule detects a suspicious crash of the Microsoft Malware Protection Engine \\\nreferences: [\'https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5\', \'https://technet.microsoft.com/en-us/library/security/4022344\'] \\\ntags: [\'attack.defense_evasion\', \'attack.t1089\', \'attack.t1211\'] \\\nauthor: Florian Roth \\\ndate:  \\\nfalsepositives: [\'MsMpEng.exe can crash when C:\\\\ is full\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = This rule detects a suspicious crash of the Microsoft Malware Protection Engine\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (((Source="Application Error" EventID="1000") OR (Source="Windows Error Reporting" EventID="1001")) (Message="*MsMpEng.exe*" OR Message="*mpengine.dll*")) | stats values(*) AS * by _time | search NOT [| inputlookup Microsoft_Malware_Protection_Engine_Crash_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1089,sigma_tag=attack.t1211,level=high"\n\n\n'
```
