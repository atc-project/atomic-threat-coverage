| Title                | Malicious Base64 encoded PowerShell Keywords in command lines                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects base64 encoded strings used in hidden malicious PowerShell command lines                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration tests</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/](http://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/)</li></ul>  |
| Author               | John Lambert (rule) |


## Detection Rules

### Sigma rule

```
title: Malicious Base64 encoded PowerShell Keywords in command lines
id: f26c6093-6f14-4b12-800f-0fcb46f5ffd0
status: experimental
description: Detects base64 encoded strings used in hidden malicious PowerShell command lines
references:
    - http://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/
tags:
    - attack.execution
    - attack.t1086
author: John Lambert (rule)
logsource:
    category: process_creation
    product: windows
detection:
    encoded:
        Image: '*\powershell.exe'
        CommandLine: '* hidden *'
    selection:
        CommandLine:
            - '*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA*'
            - '*aXRzYWRtaW4gL3RyYW5zZmVy*'
            - '*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA*'
            - '*JpdHNhZG1pbiAvdHJhbnNmZX*'
            - '*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg*'
            - '*Yml0c2FkbWluIC90cmFuc2Zlc*'
            - '*AGMAaAB1AG4AawBfAHMAaQB6AGUA*'
            - '*JABjAGgAdQBuAGsAXwBzAGkAegBlA*'
            - '*JGNodW5rX3Npem*'
            - '*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ*'
            - '*RjaHVua19zaXpl*'
            - '*Y2h1bmtfc2l6Z*'
            - '*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A*'
            - '*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg*'
            - '*lPLkNvbXByZXNzaW9u*'
            - '*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA*'
            - '*SU8uQ29tcHJlc3Npb2*'
            - '*Ty5Db21wcmVzc2lvb*'
            - '*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ*'
            - '*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA*'
            - '*lPLk1lbW9yeVN0cmVhb*'
            - '*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A*'
            - '*SU8uTWVtb3J5U3RyZWFt*'
            - '*Ty5NZW1vcnlTdHJlYW*'
            - '*4ARwBlAHQAQwBoAHUAbgBrA*'
            - '*5HZXRDaHVua*'
            - '*AEcAZQB0AEMAaAB1AG4Aaw*'
            - '*LgBHAGUAdABDAGgAdQBuAGsA*'
            - '*LkdldENodW5r*'
            - '*R2V0Q2h1bm*'
            - '*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A*'
            - '*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA*'
            - '*RIUkVBRF9JTkZPNj*'
            - '*SFJFQURfSU5GTzY0*'
            - '*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA*'
            - '*VEhSRUFEX0lORk82N*'
            - '*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA*'
            - '*cmVhdGVSZW1vdGVUaHJlYW*'
            - '*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA*'
            - '*NyZWF0ZVJlbW90ZVRocmVhZ*'
            - '*Q3JlYXRlUmVtb3RlVGhyZWFk*'
            - '*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA*'
            - '*0AZQBtAG0AbwB2AGUA*'
            - '*1lbW1vdm*'
            - '*AGUAbQBtAG8AdgBlA*'
            - '*bQBlAG0AbQBvAHYAZQ*'
            - '*bWVtbW92Z*'
            - '*ZW1tb3Zl*'
    condition: encoded and selection
falsepositives:
    - Penetration tests
level: high

```





### splunk
    
```
(Image="*\\\\powershell.exe" CommandLine="* hidden *" (CommandLine="*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA*" OR CommandLine="*aXRzYWRtaW4gL3RyYW5zZmVy*" OR CommandLine="*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA*" OR CommandLine="*JpdHNhZG1pbiAvdHJhbnNmZX*" OR CommandLine="*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg*" OR CommandLine="*Yml0c2FkbWluIC90cmFuc2Zlc*" OR CommandLine="*AGMAaAB1AG4AawBfAHMAaQB6AGUA*" OR CommandLine="*JABjAGgAdQBuAGsAXwBzAGkAegBlA*" OR CommandLine="*JGNodW5rX3Npem*" OR CommandLine="*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ*" OR CommandLine="*RjaHVua19zaXpl*" OR CommandLine="*Y2h1bmtfc2l6Z*" OR CommandLine="*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A*" OR CommandLine="*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg*" OR CommandLine="*lPLkNvbXByZXNzaW9u*" OR CommandLine="*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA*" OR CommandLine="*SU8uQ29tcHJlc3Npb2*" OR CommandLine="*Ty5Db21wcmVzc2lvb*" OR CommandLine="*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ*" OR CommandLine="*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA*" OR CommandLine="*lPLk1lbW9yeVN0cmVhb*" OR CommandLine="*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A*" OR CommandLine="*SU8uTWVtb3J5U3RyZWFt*" OR CommandLine="*Ty5NZW1vcnlTdHJlYW*" OR CommandLine="*4ARwBlAHQAQwBoAHUAbgBrA*" OR CommandLine="*5HZXRDaHVua*" OR CommandLine="*AEcAZQB0AEMAaAB1AG4Aaw*" OR CommandLine="*LgBHAGUAdABDAGgAdQBuAGsA*" OR CommandLine="*LkdldENodW5r*" OR CommandLine="*R2V0Q2h1bm*" OR CommandLine="*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A*" OR CommandLine="*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA*" OR CommandLine="*RIUkVBRF9JTkZPNj*" OR CommandLine="*SFJFQURfSU5GTzY0*" OR CommandLine="*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA*" OR CommandLine="*VEhSRUFEX0lORk82N*" OR CommandLine="*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA*" OR CommandLine="*cmVhdGVSZW1vdGVUaHJlYW*" OR CommandLine="*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA*" OR CommandLine="*NyZWF0ZVJlbW90ZVRocmVhZ*" OR CommandLine="*Q3JlYXRlUmVtb3RlVGhyZWFk*" OR CommandLine="*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA*" OR CommandLine="*0AZQBtAG0AbwB2AGUA*" OR CommandLine="*1lbW1vdm*" OR CommandLine="*AGUAbQBtAG8AdgBlA*" OR CommandLine="*bQBlAG0AbQBvAHYAZQ*" OR CommandLine="*bWVtbW92Z*" OR CommandLine="*ZW1tb3Zl*"))
```



