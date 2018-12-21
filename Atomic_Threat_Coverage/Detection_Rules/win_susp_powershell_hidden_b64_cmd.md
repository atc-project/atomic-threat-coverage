| Title                | Malicious Base64 encoded PowerShell Keywords in command lines                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects base64 encoded strings used in hidden malicious PowerShell command lines                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086](https://attack.mitre.org/tactics/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_windows_process_creation_with_commandline_4688](../Data_Needed/DN_0002_windows_process_creation_with_commandline_4688.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086](../Triggering/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Penetration tests</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[http://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/](http://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/)</li></ul>                                                          |
| Author               | John Lambert (rule)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Malicious Base64 encoded PowerShell Keywords in command lines
status: experimental
description: Detects base64 encoded strings used in hidden malicious PowerShell command lines 
references:
    - http://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/
tags:
    - attack.execution
    - attack.t1086
author: John Lambert (rule)
logsource:
    product: windows
    service: security
    description: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    encoded:
        EventID: 4688
        Image: '*\powershell.exe'
        CommandLine: '* hidden *'
    selection:
        EventID: 4688
        CommandLine:
            # bitsadmin transfer
            - '*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA*'
            - '*aXRzYWRtaW4gL3RyYW5zZmVy*'
            - '*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA*'
            - '*JpdHNhZG1pbiAvdHJhbnNmZX*'
            - '*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg*'
            - '*Yml0c2FkbWluIC90cmFuc2Zlc*'
            # chunk_size
            - '*AGMAaAB1AG4AawBfAHMAaQB6AGUA*'
            - '*JABjAGgAdQBuAGsAXwBzAGkAegBlA*'
            - '*JGNodW5rX3Npem*'
            - '*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ*'
            - '*RjaHVua19zaXpl*'
            - '*Y2h1bmtfc2l6Z*'
            # IO.Compression
            - '*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A*'
            - '*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg*'
            - '*lPLkNvbXByZXNzaW9u*'
            - '*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA*'
            - '*SU8uQ29tcHJlc3Npb2*'
            - '*Ty5Db21wcmVzc2lvb*'
            # IO.MemoryStream
            - '*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ*'
            - '*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA*'
            - '*lPLk1lbW9yeVN0cmVhb*'
            - '*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A*'
            - '*SU8uTWVtb3J5U3RyZWFt*'
            - '*Ty5NZW1vcnlTdHJlYW*'
            # GetChunk
            - '*4ARwBlAHQAQwBoAHUAbgBrA*'
            - '*5HZXRDaHVua*'
            - '*AEcAZQB0AEMAaAB1AG4Aaw*'
            - '*LgBHAGUAdABDAGgAdQBuAGsA*'
            - '*LkdldENodW5r*'
            - '*R2V0Q2h1bm*'
            # THREAD INFO64
            - '*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A*'
            - '*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA*'
            - '*RIUkVBRF9JTkZPNj*'
            - '*SFJFQURfSU5GTzY0*'
            - '*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA*'
            - '*VEhSRUFEX0lORk82N*'
            # CreateRemoteThread
            - '*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA*'
            - '*cmVhdGVSZW1vdGVUaHJlYW*'
            - '*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA*'
            - '*NyZWF0ZVJlbW90ZVRocmVhZ*'
            - '*Q3JlYXRlUmVtb3RlVGhyZWFk*'
            - '*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA*'
            # memmove
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





### Kibana query

```
(EventID:"4688" AND Image:"*\\\\powershell.exe" AND CommandLine:"* hidden *" AND CommandLine:("*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA*" "*aXRzYWRtaW4gL3RyYW5zZmVy*" "*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA*" "*JpdHNhZG1pbiAvdHJhbnNmZX*" "*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg*" "*Yml0c2FkbWluIC90cmFuc2Zlc*" "*AGMAaAB1AG4AawBfAHMAaQB6AGUA*" "*JABjAGgAdQBuAGsAXwBzAGkAegBlA*" "*JGNodW5rX3Npem*" "*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ*" "*RjaHVua19zaXpl*" "*Y2h1bmtfc2l6Z*" "*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A*" "*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg*" "*lPLkNvbXByZXNzaW9u*" "*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA*" "*SU8uQ29tcHJlc3Npb2*" "*Ty5Db21wcmVzc2lvb*" "*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ*" "*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA*" "*lPLk1lbW9yeVN0cmVhb*" "*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A*" "*SU8uTWVtb3J5U3RyZWFt*" "*Ty5NZW1vcnlTdHJlYW*" "*4ARwBlAHQAQwBoAHUAbgBrA*" "*5HZXRDaHVua*" "*AEcAZQB0AEMAaAB1AG4Aaw*" "*LgBHAGUAdABDAGgAdQBuAGsA*" "*LkdldENodW5r*" "*R2V0Q2h1bm*" "*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A*" "*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA*" "*RIUkVBRF9JTkZPNj*" "*SFJFQURfSU5GTzY0*" "*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA*" "*VEhSRUFEX0lORk82N*" "*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA*" "*cmVhdGVSZW1vdGVUaHJlYW*" "*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA*" "*NyZWF0ZVJlbW90ZVRocmVhZ*" "*Q3JlYXRlUmVtb3RlVGhyZWFk*" "*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA*" "*0AZQBtAG0AbwB2AGUA*" "*1lbW1vdm*" "*AGUAbQBtAG8AdgBlA*" "*bQBlAG0AbQBvAHYAZQ*" "*bWVtbW92Z*" "*ZW1tb3Zl*"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Malicious-Base64-encoded-PowerShell-Keywords-in-command-lines <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND Image:\\"*\\\\\\\\powershell.exe\\" AND CommandLine:\\"* hidden *\\" AND CommandLine:(\\"*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA*\\" \\"*aXRzYWRtaW4gL3RyYW5zZmVy*\\" \\"*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA*\\" \\"*JpdHNhZG1pbiAvdHJhbnNmZX*\\" \\"*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg*\\" \\"*Yml0c2FkbWluIC90cmFuc2Zlc*\\" \\"*AGMAaAB1AG4AawBfAHMAaQB6AGUA*\\" \\"*JABjAGgAdQBuAGsAXwBzAGkAegBlA*\\" \\"*JGNodW5rX3Npem*\\" \\"*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ*\\" \\"*RjaHVua19zaXpl*\\" \\"*Y2h1bmtfc2l6Z*\\" \\"*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A*\\" \\"*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg*\\" \\"*lPLkNvbXByZXNzaW9u*\\" \\"*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA*\\" \\"*SU8uQ29tcHJlc3Npb2*\\" \\"*Ty5Db21wcmVzc2lvb*\\" \\"*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ*\\" \\"*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA*\\" \\"*lPLk1lbW9yeVN0cmVhb*\\" \\"*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A*\\" \\"*SU8uTWVtb3J5U3RyZWFt*\\" \\"*Ty5NZW1vcnlTdHJlYW*\\" \\"*4ARwBlAHQAQwBoAHUAbgBrA*\\" \\"*5HZXRDaHVua*\\" \\"*AEcAZQB0AEMAaAB1AG4Aaw*\\" \\"*LgBHAGUAdABDAGgAdQBuAGsA*\\" \\"*LkdldENodW5r*\\" \\"*R2V0Q2h1bm*\\" \\"*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A*\\" \\"*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA*\\" \\"*RIUkVBRF9JTkZPNj*\\" \\"*SFJFQURfSU5GTzY0*\\" \\"*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA*\\" \\"*VEhSRUFEX0lORk82N*\\" \\"*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA*\\" \\"*cmVhdGVSZW1vdGVUaHJlYW*\\" \\"*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA*\\" \\"*NyZWF0ZVJlbW90ZVRocmVhZ*\\" \\"*Q3JlYXRlUmVtb3RlVGhyZWFk*\\" \\"*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA*\\" \\"*0AZQBtAG0AbwB2AGUA*\\" \\"*1lbW1vdm*\\" \\"*AGUAbQBtAG8AdgBlA*\\" \\"*bQBlAG0AbQBvAHYAZQ*\\" \\"*bWVtbW92Z*\\" \\"*ZW1tb3Zl*\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Malicious Base64 encoded PowerShell Keywords in command lines\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"4688" AND Image:"*\\\\powershell.exe" AND CommandLine:"* hidden *" AND CommandLine:("*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA*" "*aXRzYWRtaW4gL3RyYW5zZmVy*" "*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA*" "*JpdHNhZG1pbiAvdHJhbnNmZX*" "*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg*" "*Yml0c2FkbWluIC90cmFuc2Zlc*" "*AGMAaAB1AG4AawBfAHMAaQB6AGUA*" "*JABjAGgAdQBuAGsAXwBzAGkAegBlA*" "*JGNodW5rX3Npem*" "*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ*" "*RjaHVua19zaXpl*" "*Y2h1bmtfc2l6Z*" "*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A*" "*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg*" "*lPLkNvbXByZXNzaW9u*" "*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA*" "*SU8uQ29tcHJlc3Npb2*" "*Ty5Db21wcmVzc2lvb*" "*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ*" "*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA*" "*lPLk1lbW9yeVN0cmVhb*" "*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A*" "*SU8uTWVtb3J5U3RyZWFt*" "*Ty5NZW1vcnlTdHJlYW*" "*4ARwBlAHQAQwBoAHUAbgBrA*" "*5HZXRDaHVua*" "*AEcAZQB0AEMAaAB1AG4Aaw*" "*LgBHAGUAdABDAGgAdQBuAGsA*" "*LkdldENodW5r*" "*R2V0Q2h1bm*" "*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A*" "*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA*" "*RIUkVBRF9JTkZPNj*" "*SFJFQURfSU5GTzY0*" "*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA*" "*VEhSRUFEX0lORk82N*" "*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA*" "*cmVhdGVSZW1vdGVUaHJlYW*" "*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA*" "*NyZWF0ZVJlbW90ZVRocmVhZ*" "*Q3JlYXRlUmVtb3RlVGhyZWFk*" "*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA*" "*0AZQBtAG0AbwB2AGUA*" "*1lbW1vdm*" "*AGUAbQBtAG8AdgBlA*" "*bQBlAG0AbQBvAHYAZQ*" "*bWVtbW92Z*" "*ZW1tb3Zl*"))
```

