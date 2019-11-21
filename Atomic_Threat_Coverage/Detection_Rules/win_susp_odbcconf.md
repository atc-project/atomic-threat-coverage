| Title                | Possible Application Whitelisting Bypass via dll loaded by odbcconf.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects defence evasion attempt via odbcconf.exe execution to load DLL                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate use of odbcconf.exe by legitimate user</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Odbcconf.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Odbcconf.yml)</li><li>[https://twitter.com/Hexacorn/status/1187143326673330176](https://twitter.com/Hexacorn/status/1187143326673330176)</li></ul>  |
| Author               | Kirill Kiryanov, Beyu Denis, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Possible Application Whitelisting Bypass via dll loaded by odbcconf.exe
id: 65d2be45-8600-4042-b4c0-577a1ff8a60e
description: Detects defence evasion attempt via odbcconf.exe execution to load DLL
status: experimental
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Odbcconf.yml
    - https://twitter.com/Hexacorn/status/1187143326673330176
author: Kirill Kiryanov, Beyu Denis, Daniil Yugoslavskiy, oscd.community
date: 2019/10/25
modified: 2019/11/07
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: '\odbcconf.exe'
        CommandLine|contains: 
            - '-f'
            - 'regsvr'
    selection_2:
        ParentImage|endswith: '\odbcconf.exe'
        Image|endswith: '\rundll32.exe'
    condition: selection_1 or selection_2
level: medium
falsepositives:
    - Legitimate use of odbcconf.exe by legitimate user

```





### splunk
    
```
((Image="*\\\\odbcconf.exe" (CommandLine="*-f*" OR CommandLine="*regsvr*")) OR (ParentImage="*\\\\odbcconf.exe" Image="*\\\\rundll32.exe"))
```



