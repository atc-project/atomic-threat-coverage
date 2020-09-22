| Title                    | Malicious Base64 Encoded PowerShell Keywords in Command Lines       |
|:-------------------------|:------------------|
| **Description**          | Detects base64 encoded strings used in hidden malicious PowerShell command lines |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059.001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Penetration tests</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[http://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/](http://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/)</li></ul>  |
| **Author**               | John Lambert (rule) |


## Detection Rules

### Sigma rule

```
title: Malicious Base64 Encoded PowerShell Keywords in Command Lines
id: f26c6093-6f14-4b12-800f-0fcb46f5ffd0
status: experimental
description: Detects base64 encoded strings used in hidden malicious PowerShell command lines
references:
    - http://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086      # an old one
author: John Lambert (rule)
date: 2019/01/16
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





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\powershell.exe" -and $_.message -match "CommandLine.*.* hidden .*" -and ($_.message -match "CommandLine.*.*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA.*" -or $_.message -match "CommandLine.*.*aXRzYWRtaW4gL3RyYW5zZmVy.*" -or $_.message -match "CommandLine.*.*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA.*" -or $_.message -match "CommandLine.*.*JpdHNhZG1pbiAvdHJhbnNmZX.*" -or $_.message -match "CommandLine.*.*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg.*" -or $_.message -match "CommandLine.*.*Yml0c2FkbWluIC90cmFuc2Zlc.*" -or $_.message -match "CommandLine.*.*AGMAaAB1AG4AawBfAHMAaQB6AGUA.*" -or $_.message -match "CommandLine.*.*JABjAGgAdQBuAGsAXwBzAGkAegBlA.*" -or $_.message -match "CommandLine.*.*JGNodW5rX3Npem.*" -or $_.message -match "CommandLine.*.*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ.*" -or $_.message -match "CommandLine.*.*RjaHVua19zaXpl.*" -or $_.message -match "CommandLine.*.*Y2h1bmtfc2l6Z.*" -or $_.message -match "CommandLine.*.*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A.*" -or $_.message -match "CommandLine.*.*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg.*" -or $_.message -match "CommandLine.*.*lPLkNvbXByZXNzaW9u.*" -or $_.message -match "CommandLine.*.*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA.*" -or $_.message -match "CommandLine.*.*SU8uQ29tcHJlc3Npb2.*" -or $_.message -match "CommandLine.*.*Ty5Db21wcmVzc2lvb.*" -or $_.message -match "CommandLine.*.*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ.*" -or $_.message -match "CommandLine.*.*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA.*" -or $_.message -match "CommandLine.*.*lPLk1lbW9yeVN0cmVhb.*" -or $_.message -match "CommandLine.*.*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A.*" -or $_.message -match "CommandLine.*.*SU8uTWVtb3J5U3RyZWFt.*" -or $_.message -match "CommandLine.*.*Ty5NZW1vcnlTdHJlYW.*" -or $_.message -match "CommandLine.*.*4ARwBlAHQAQwBoAHUAbgBrA.*" -or $_.message -match "CommandLine.*.*5HZXRDaHVua.*" -or $_.message -match "CommandLine.*.*AEcAZQB0AEMAaAB1AG4Aaw.*" -or $_.message -match "CommandLine.*.*LgBHAGUAdABDAGgAdQBuAGsA.*" -or $_.message -match "CommandLine.*.*LkdldENodW5r.*" -or $_.message -match "CommandLine.*.*R2V0Q2h1bm.*" -or $_.message -match "CommandLine.*.*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A.*" -or $_.message -match "CommandLine.*.*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA.*" -or $_.message -match "CommandLine.*.*RIUkVBRF9JTkZPNj.*" -or $_.message -match "CommandLine.*.*SFJFQURfSU5GTzY0.*" -or $_.message -match "CommandLine.*.*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA.*" -or $_.message -match "CommandLine.*.*VEhSRUFEX0lORk82N.*" -or $_.message -match "CommandLine.*.*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA.*" -or $_.message -match "CommandLine.*.*cmVhdGVSZW1vdGVUaHJlYW.*" -or $_.message -match "CommandLine.*.*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA.*" -or $_.message -match "CommandLine.*.*NyZWF0ZVJlbW90ZVRocmVhZ.*" -or $_.message -match "CommandLine.*.*Q3JlYXRlUmVtb3RlVGhyZWFk.*" -or $_.message -match "CommandLine.*.*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA.*" -or $_.message -match "CommandLine.*.*0AZQBtAG0AbwB2AGUA.*" -or $_.message -match "CommandLine.*.*1lbW1vdm.*" -or $_.message -match "CommandLine.*.*AGUAbQBtAG8AdgBlA.*" -or $_.message -match "CommandLine.*.*bQBlAG0AbQBvAHYAZQ.*" -or $_.message -match "CommandLine.*.*bWVtbW92Z.*" -or $_.message -match "CommandLine.*.*ZW1tb3Zl.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*\\ hidden\\ * AND winlog.event_data.CommandLine.keyword:(*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA* OR *aXRzYWRtaW4gL3RyYW5zZmVy* OR *IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA* OR *JpdHNhZG1pbiAvdHJhbnNmZX* OR *YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg* OR *Yml0c2FkbWluIC90cmFuc2Zlc* OR *AGMAaAB1AG4AawBfAHMAaQB6AGUA* OR *JABjAGgAdQBuAGsAXwBzAGkAegBlA* OR *JGNodW5rX3Npem* OR *QAYwBoAHUAbgBrAF8AcwBpAHoAZQ* OR *RjaHVua19zaXpl* OR *Y2h1bmtfc2l6Z* OR *AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A* OR *kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg* OR *lPLkNvbXByZXNzaW9u* OR *SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA* OR *SU8uQ29tcHJlc3Npb2* OR *Ty5Db21wcmVzc2lvb* OR *AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ* OR *kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA* OR *lPLk1lbW9yeVN0cmVhb* OR *SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A* OR *SU8uTWVtb3J5U3RyZWFt* OR *Ty5NZW1vcnlTdHJlYW* OR *4ARwBlAHQAQwBoAHUAbgBrA* OR *5HZXRDaHVua* OR *AEcAZQB0AEMAaAB1AG4Aaw* OR *LgBHAGUAdABDAGgAdQBuAGsA* OR *LkdldENodW5r* OR *R2V0Q2h1bm* OR *AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A* OR *QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA* OR *RIUkVBRF9JTkZPNj* OR *SFJFQURfSU5GTzY0* OR *VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA* OR *VEhSRUFEX0lORk82N* OR *AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA* OR *cmVhdGVSZW1vdGVUaHJlYW* OR *MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA* OR *NyZWF0ZVJlbW90ZVRocmVhZ* OR *Q3JlYXRlUmVtb3RlVGhyZWFk* OR *QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA* OR *0AZQBtAG0AbwB2AGUA* OR *1lbW1vdm* OR *AGUAbQBtAG8AdgBlA* OR *bQBlAG0AbQBvAHYAZQ* OR *bWVtbW92Z* OR *ZW1tb3Zl*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/f26c6093-6f14-4b12-800f-0fcb46f5ffd0 <<EOF\n{\n  "metadata": {\n    "title": "Malicious Base64 Encoded PowerShell Keywords in Command Lines",\n    "description": "Detects base64 encoded strings used in hidden malicious PowerShell command lines",\n    "tags": [\n      "attack.execution",\n      "attack.t1059.001",\n      "attack.t1086"\n    ],\n    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*\\\\ hidden\\\\ * AND winlog.event_data.CommandLine.keyword:(*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA* OR *aXRzYWRtaW4gL3RyYW5zZmVy* OR *IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA* OR *JpdHNhZG1pbiAvdHJhbnNmZX* OR *YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg* OR *Yml0c2FkbWluIC90cmFuc2Zlc* OR *AGMAaAB1AG4AawBfAHMAaQB6AGUA* OR *JABjAGgAdQBuAGsAXwBzAGkAegBlA* OR *JGNodW5rX3Npem* OR *QAYwBoAHUAbgBrAF8AcwBpAHoAZQ* OR *RjaHVua19zaXpl* OR *Y2h1bmtfc2l6Z* OR *AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A* OR *kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg* OR *lPLkNvbXByZXNzaW9u* OR *SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA* OR *SU8uQ29tcHJlc3Npb2* OR *Ty5Db21wcmVzc2lvb* OR *AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ* OR *kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA* OR *lPLk1lbW9yeVN0cmVhb* OR *SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A* OR *SU8uTWVtb3J5U3RyZWFt* OR *Ty5NZW1vcnlTdHJlYW* OR *4ARwBlAHQAQwBoAHUAbgBrA* OR *5HZXRDaHVua* OR *AEcAZQB0AEMAaAB1AG4Aaw* OR *LgBHAGUAdABDAGgAdQBuAGsA* OR *LkdldENodW5r* OR *R2V0Q2h1bm* OR *AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A* OR *QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA* OR *RIUkVBRF9JTkZPNj* OR *SFJFQURfSU5GTzY0* OR *VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA* OR *VEhSRUFEX0lORk82N* OR *AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA* OR *cmVhdGVSZW1vdGVUaHJlYW* OR *MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA* OR *NyZWF0ZVJlbW90ZVRocmVhZ* OR *Q3JlYXRlUmVtb3RlVGhyZWFk* OR *QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA* OR *0AZQBtAG0AbwB2AGUA* OR *1lbW1vdm* OR *AGUAbQBtAG8AdgBlA* OR *bQBlAG0AbQBvAHYAZQ* OR *bWVtbW92Z* OR *ZW1tb3Zl*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*\\\\ hidden\\\\ * AND winlog.event_data.CommandLine.keyword:(*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA* OR *aXRzYWRtaW4gL3RyYW5zZmVy* OR *IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA* OR *JpdHNhZG1pbiAvdHJhbnNmZX* OR *YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg* OR *Yml0c2FkbWluIC90cmFuc2Zlc* OR *AGMAaAB1AG4AawBfAHMAaQB6AGUA* OR *JABjAGgAdQBuAGsAXwBzAGkAegBlA* OR *JGNodW5rX3Npem* OR *QAYwBoAHUAbgBrAF8AcwBpAHoAZQ* OR *RjaHVua19zaXpl* OR *Y2h1bmtfc2l6Z* OR *AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A* OR *kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg* OR *lPLkNvbXByZXNzaW9u* OR *SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA* OR *SU8uQ29tcHJlc3Npb2* OR *Ty5Db21wcmVzc2lvb* OR *AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ* OR *kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA* OR *lPLk1lbW9yeVN0cmVhb* OR *SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A* OR *SU8uTWVtb3J5U3RyZWFt* OR *Ty5NZW1vcnlTdHJlYW* OR *4ARwBlAHQAQwBoAHUAbgBrA* OR *5HZXRDaHVua* OR *AEcAZQB0AEMAaAB1AG4Aaw* OR *LgBHAGUAdABDAGgAdQBuAGsA* OR *LkdldENodW5r* OR *R2V0Q2h1bm* OR *AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A* OR *QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA* OR *RIUkVBRF9JTkZPNj* OR *SFJFQURfSU5GTzY0* OR *VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA* OR *VEhSRUFEX0lORk82N* OR *AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA* OR *cmVhdGVSZW1vdGVUaHJlYW* OR *MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA* OR *NyZWF0ZVJlbW90ZVRocmVhZ* OR *Q3JlYXRlUmVtb3RlVGhyZWFk* OR *QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA* OR *0AZQBtAG0AbwB2AGUA* OR *1lbW1vdm* OR *AGUAbQBtAG8AdgBlA* OR *bQBlAG0AbQBvAHYAZQ* OR *bWVtbW92Z* OR *ZW1tb3Zl*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Malicious Base64 Encoded PowerShell Keywords in Command Lines\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\powershell.exe AND CommandLine.keyword:* hidden * AND CommandLine.keyword:(*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA* *aXRzYWRtaW4gL3RyYW5zZmVy* *IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA* *JpdHNhZG1pbiAvdHJhbnNmZX* *YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg* *Yml0c2FkbWluIC90cmFuc2Zlc* *AGMAaAB1AG4AawBfAHMAaQB6AGUA* *JABjAGgAdQBuAGsAXwBzAGkAegBlA* *JGNodW5rX3Npem* *QAYwBoAHUAbgBrAF8AcwBpAHoAZQ* *RjaHVua19zaXpl* *Y2h1bmtfc2l6Z* *AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A* *kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg* *lPLkNvbXByZXNzaW9u* *SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA* *SU8uQ29tcHJlc3Npb2* *Ty5Db21wcmVzc2lvb* *AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ* *kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA* *lPLk1lbW9yeVN0cmVhb* *SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A* *SU8uTWVtb3J5U3RyZWFt* *Ty5NZW1vcnlTdHJlYW* *4ARwBlAHQAQwBoAHUAbgBrA* *5HZXRDaHVua* *AEcAZQB0AEMAaAB1AG4Aaw* *LgBHAGUAdABDAGgAdQBuAGsA* *LkdldENodW5r* *R2V0Q2h1bm* *AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A* *QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA* *RIUkVBRF9JTkZPNj* *SFJFQURfSU5GTzY0* *VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA* *VEhSRUFEX0lORk82N* *AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA* *cmVhdGVSZW1vdGVUaHJlYW* *MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA* *NyZWF0ZVJlbW90ZVRocmVhZ* *Q3JlYXRlUmVtb3RlVGhyZWFk* *QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA* *0AZQBtAG0AbwB2AGUA* *1lbW1vdm* *AGUAbQBtAG8AdgBlA* *bQBlAG0AbQBvAHYAZQ* *bWVtbW92Z* *ZW1tb3Zl*))
```


### splunk
    
```
(Image="*\\\\powershell.exe" CommandLine="* hidden *" (CommandLine="*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA*" OR CommandLine="*aXRzYWRtaW4gL3RyYW5zZmVy*" OR CommandLine="*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA*" OR CommandLine="*JpdHNhZG1pbiAvdHJhbnNmZX*" OR CommandLine="*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg*" OR CommandLine="*Yml0c2FkbWluIC90cmFuc2Zlc*" OR CommandLine="*AGMAaAB1AG4AawBfAHMAaQB6AGUA*" OR CommandLine="*JABjAGgAdQBuAGsAXwBzAGkAegBlA*" OR CommandLine="*JGNodW5rX3Npem*" OR CommandLine="*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ*" OR CommandLine="*RjaHVua19zaXpl*" OR CommandLine="*Y2h1bmtfc2l6Z*" OR CommandLine="*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A*" OR CommandLine="*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg*" OR CommandLine="*lPLkNvbXByZXNzaW9u*" OR CommandLine="*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA*" OR CommandLine="*SU8uQ29tcHJlc3Npb2*" OR CommandLine="*Ty5Db21wcmVzc2lvb*" OR CommandLine="*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ*" OR CommandLine="*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA*" OR CommandLine="*lPLk1lbW9yeVN0cmVhb*" OR CommandLine="*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A*" OR CommandLine="*SU8uTWVtb3J5U3RyZWFt*" OR CommandLine="*Ty5NZW1vcnlTdHJlYW*" OR CommandLine="*4ARwBlAHQAQwBoAHUAbgBrA*" OR CommandLine="*5HZXRDaHVua*" OR CommandLine="*AEcAZQB0AEMAaAB1AG4Aaw*" OR CommandLine="*LgBHAGUAdABDAGgAdQBuAGsA*" OR CommandLine="*LkdldENodW5r*" OR CommandLine="*R2V0Q2h1bm*" OR CommandLine="*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A*" OR CommandLine="*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA*" OR CommandLine="*RIUkVBRF9JTkZPNj*" OR CommandLine="*SFJFQURfSU5GTzY0*" OR CommandLine="*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA*" OR CommandLine="*VEhSRUFEX0lORk82N*" OR CommandLine="*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA*" OR CommandLine="*cmVhdGVSZW1vdGVUaHJlYW*" OR CommandLine="*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA*" OR CommandLine="*NyZWF0ZVJlbW90ZVRocmVhZ*" OR CommandLine="*Q3JlYXRlUmVtb3RlVGhyZWFk*" OR CommandLine="*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA*" OR CommandLine="*0AZQBtAG0AbwB2AGUA*" OR CommandLine="*1lbW1vdm*" OR CommandLine="*AGUAbQBtAG8AdgBlA*" OR CommandLine="*bQBlAG0AbQBvAHYAZQ*" OR CommandLine="*bWVtbW92Z*" OR CommandLine="*ZW1tb3Zl*"))
```


### logpoint
    
```
(Image="*\\\\powershell.exe" CommandLine="* hidden *" CommandLine IN ["*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA*", "*aXRzYWRtaW4gL3RyYW5zZmVy*", "*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA*", "*JpdHNhZG1pbiAvdHJhbnNmZX*", "*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg*", "*Yml0c2FkbWluIC90cmFuc2Zlc*", "*AGMAaAB1AG4AawBfAHMAaQB6AGUA*", "*JABjAGgAdQBuAGsAXwBzAGkAegBlA*", "*JGNodW5rX3Npem*", "*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ*", "*RjaHVua19zaXpl*", "*Y2h1bmtfc2l6Z*", "*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A*", "*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg*", "*lPLkNvbXByZXNzaW9u*", "*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA*", "*SU8uQ29tcHJlc3Npb2*", "*Ty5Db21wcmVzc2lvb*", "*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ*", "*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA*", "*lPLk1lbW9yeVN0cmVhb*", "*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A*", "*SU8uTWVtb3J5U3RyZWFt*", "*Ty5NZW1vcnlTdHJlYW*", "*4ARwBlAHQAQwBoAHUAbgBrA*", "*5HZXRDaHVua*", "*AEcAZQB0AEMAaAB1AG4Aaw*", "*LgBHAGUAdABDAGgAdQBuAGsA*", "*LkdldENodW5r*", "*R2V0Q2h1bm*", "*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A*", "*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA*", "*RIUkVBRF9JTkZPNj*", "*SFJFQURfSU5GTzY0*", "*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA*", "*VEhSRUFEX0lORk82N*", "*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA*", "*cmVhdGVSZW1vdGVUaHJlYW*", "*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA*", "*NyZWF0ZVJlbW90ZVRocmVhZ*", "*Q3JlYXRlUmVtb3RlVGhyZWFk*", "*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA*", "*0AZQBtAG0AbwB2AGUA*", "*1lbW1vdm*", "*AGUAbQBtAG8AdgBlA*", "*bQBlAG0AbQBvAHYAZQ*", "*bWVtbW92Z*", "*ZW1tb3Zl*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\powershell\\.exe)(?=.*.* hidden .*)(?=.*(?:.*.*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA.*|.*.*aXRzYWRtaW4gL3RyYW5zZmVy.*|.*.*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA.*|.*.*JpdHNhZG1pbiAvdHJhbnNmZX.*|.*.*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg.*|.*.*Yml0c2FkbWluIC90cmFuc2Zlc.*|.*.*AGMAaAB1AG4AawBfAHMAaQB6AGUA.*|.*.*JABjAGgAdQBuAGsAXwBzAGkAegBlA.*|.*.*JGNodW5rX3Npem.*|.*.*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ.*|.*.*RjaHVua19zaXpl.*|.*.*Y2h1bmtfc2l6Z.*|.*.*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A.*|.*.*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg.*|.*.*lPLkNvbXByZXNzaW9u.*|.*.*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA.*|.*.*SU8uQ29tcHJlc3Npb2.*|.*.*Ty5Db21wcmVzc2lvb.*|.*.*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ.*|.*.*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA.*|.*.*lPLk1lbW9yeVN0cmVhb.*|.*.*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A.*|.*.*SU8uTWVtb3J5U3RyZWFt.*|.*.*Ty5NZW1vcnlTdHJlYW.*|.*.*4ARwBlAHQAQwBoAHUAbgBrA.*|.*.*5HZXRDaHVua.*|.*.*AEcAZQB0AEMAaAB1AG4Aaw.*|.*.*LgBHAGUAdABDAGgAdQBuAGsA.*|.*.*LkdldENodW5r.*|.*.*R2V0Q2h1bm.*|.*.*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A.*|.*.*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA.*|.*.*RIUkVBRF9JTkZPNj.*|.*.*SFJFQURfSU5GTzY0.*|.*.*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA.*|.*.*VEhSRUFEX0lORk82N.*|.*.*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA.*|.*.*cmVhdGVSZW1vdGVUaHJlYW.*|.*.*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA.*|.*.*NyZWF0ZVJlbW90ZVRocmVhZ.*|.*.*Q3JlYXRlUmVtb3RlVGhyZWFk.*|.*.*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA.*|.*.*0AZQBtAG0AbwB2AGUA.*|.*.*1lbW1vdm.*|.*.*AGUAbQBtAG8AdgBlA.*|.*.*bQBlAG0AbQBvAHYAZQ.*|.*.*bWVtbW92Z.*|.*.*ZW1tb3Zl.*)))'
```



