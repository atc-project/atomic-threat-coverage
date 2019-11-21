| Title                | Possible Application Whitelisting Bypass via WinDbg/CDB as a shellcode runner                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Launch 64-bit shellcode from the x64_calc.wds file using cdb.exe.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate use of debugging tools</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Cdb.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Cdb.yml)</li><li>[http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)</li></ul>  |
| Author               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Possible Application Whitelisting Bypass via WinDbg/CDB as a shellcode runner
id: b5c7395f-e501-4a08-94d4-57fe7a9da9d2
status: experimental
description: Launch 64-bit shellcode from the x64_calc.wds file using cdb.exe.
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Cdb.yml
    - http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html
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
        Image|endswith: '\cdb.exe'
        CommandLine|contains: '-cf'
    condition: selection
falsepositives:
    - Legitimate use of debugging tools

```





### splunk
    
```
(Image="*\\\\cdb.exe" CommandLine="*-cf*")
```



