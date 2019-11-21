| Title                | Application Whitelisting bypass via dnx.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Execute C# code located in the consoleapp folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate use of dnx.exe by legitimate user</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml)</li><li>[https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/](https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/)</li></ul>  |
| Author               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Application Whitelisting bypass via dnx.exe
id: 81ebd28b-9607-4478-bf06-974ed9d53ed7
status: experimental
description: Execute C# code located in the consoleapp folder
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml
    - https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/
author: Beyu Denis, oscd.community
date: 2019/10/26
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\dnx.exe'
    condition: selection
falsepositives:
    - Legitimate use of dnx.exe by legitimate user

```





### splunk
    
```
Image="*\\\\dnx.exe"
```



