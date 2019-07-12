| Title                | Mimikatz Detection LSASS Access                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects process access to LSASS which is typical for Mimikatz (0x1000 PROCESS_QUERY_ LIMITED_INFORMATION, 0x0400 PROCESS_QUERY_ INFORMATION "only old versions", 0x0010 PROCESS_VM_READ)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://onedrive.live.com/view.aspx?resid=D026B4699190F1E6!2843&ithint=file%2cpptx&app=PowerPoint&authkey=!AMvCRTKB_V1J5ow](https://onedrive.live.com/view.aspx?resid=D026B4699190F1E6!2843&ithint=file%2cpptx&app=PowerPoint&authkey=!AMvCRTKB_V1J5ow)</li><li>[https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html)</li></ul>  |
| Author               |  Author of this Detection Rule haven't introduced himself  |
| Other Tags           | <ul><li>attack.s0002</li><li>attack.s0002</li><li>car.2019-04-004</li><li>car.2019-04-004</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Mimikatz Detection LSASS Access
status: experimental
description: Detects process access to LSASS which is typical for Mimikatz (0x1000 PROCESS_QUERY_ LIMITED_INFORMATION, 0x0400 PROCESS_QUERY_ INFORMATION "only old versions", 0x0010 PROCESS_VM_READ)
references:
    - https://onedrive.live.com/view.aspx?resid=D026B4699190F1E6!2843&ithint=file%2cpptx&app=PowerPoint&authkey=!AMvCRTKB_V1J5ow
    - https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
tags:
    - attack.t1003
    - attack.s0002
    - attack.credential_access
    - car.2019-04-004
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage: 'C:\windows\system32\lsass.exe'
        GrantedAccess:
            - '0x1410'      
            - '0x1010'      
    condition: selection
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
(EventID:"10" AND TargetImage:"C\\:\\\\windows\\\\system32\\\\lsass.exe" AND GrantedAccess:("0x1410" "0x1010"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Mimikatz-Detection-LSASS-Access <<EOF\n{\n  "metadata": {\n    "title": "Mimikatz Detection LSASS Access",\n    "description": "Detects process access to LSASS which is typical for Mimikatz (0x1000 PROCESS_QUERY_ LIMITED_INFORMATION, 0x0400 PROCESS_QUERY_ INFORMATION \\"only old versions\\", 0x0010 PROCESS_VM_READ)",\n    "tags": [\n      "attack.t1003",\n      "attack.s0002",\n      "attack.credential_access",\n      "car.2019-04-004"\n    ],\n    "query": "(EventID:\\"10\\" AND TargetImage:\\"C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\lsass.exe\\" AND GrantedAccess:(\\"0x1410\\" \\"0x1010\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"10\\" AND TargetImage:\\"C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\lsass.exe\\" AND GrantedAccess:(\\"0x1410\\" \\"0x1010\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Mimikatz Detection LSASS Access\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"10" AND TargetImage:"C\\:\\\\windows\\\\system32\\\\lsass.exe" AND GrantedAccess:("0x1410" "0x1010"))
```


### splunk
    
```
(EventID="10" TargetImage="C:\\\\windows\\\\system32\\\\lsass.exe" (GrantedAccess="0x1410" OR GrantedAccess="0x1010"))
```


### logpoint
    
```
(EventID="10" TargetImage="C:\\\\windows\\\\system32\\\\lsass.exe" GrantedAccess IN ["0x1410", "0x1010"])
```


### grep
    
```
grep -P '^(?:.*(?=.*10)(?=.*C:\\windows\\system32\\lsass\\.exe)(?=.*(?:.*0x1410|.*0x1010)))'
```



