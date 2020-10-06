| Title                    | Cred Dump-Tools Named Pipes       |
|:-------------------------|:------------------|
| **Description**          | Detects well-known credential dumping tools execution via specific named pipes |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1003.001: LSASS Memory](https://attack.mitre.org/techniques/T1003/001)</li><li>[T1003.002: Security Account Manager](https://attack.mitre.org/techniques/T1003/002)</li><li>[T1003.004: LSA Secrets](https://attack.mitre.org/techniques/T1003/004)</li><li>[T1003.005: Cached Domain Credentials](https://attack.mitre.org/techniques/T1003/005)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0020_17_windows_sysmon_PipeEvent](../Data_Needed/DN_0020_17_windows_sysmon_PipeEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li><li>[T1003.001: LSASS Memory](../Triggers/T1003.001.md)</li><li>[T1003.002: Security Account Manager](../Triggers/T1003.002.md)</li><li>[T1003.004: LSA Secrets](../Triggers/T1003.004.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Legitimate Administrator using tool for password recovery</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Cred Dump-Tools Named Pipes
id: 961d0ba2-3eea-4303-a930-2cf78bbfcc5e
description: Detects well-known credential dumping tools execution via specific named pipes
author: Teymur Kheirkhabarov, oscd.community
date: 2019/11/01
modified: 2020/08/28
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003          # an old one
    - attack.t1003.001
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.005
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 17
        PipeName|contains:
            - '\lsadump'
            - '\cachedump'
            - '\wceservicepipe'
    condition: selection
falsepositives:
    - Legitimate Administrator using tool for password recovery
level: critical
status: experimental

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "17" -and ($_.message -match "PipeName.*.*\\\\lsadump.*" -or $_.message -match "PipeName.*.*\\\\cachedump.*" -or $_.message -match "PipeName.*.*\\\\wceservicepipe.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND winlog.event_id:"17" AND winlog.event_data.PipeName.keyword:(*\\\\lsadump* OR *\\\\cachedump* OR *\\\\wceservicepipe*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/961d0ba2-3eea-4303-a930-2cf78bbfcc5e <<EOF\n{\n  "metadata": {\n    "title": "Cred Dump-Tools Named Pipes",\n    "description": "Detects well-known credential dumping tools execution via specific named pipes",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003",\n      "attack.t1003.001",\n      "attack.t1003.002",\n      "attack.t1003.004",\n      "attack.t1003.005"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"17\\" AND winlog.event_data.PipeName.keyword:(*\\\\\\\\lsadump* OR *\\\\\\\\cachedump* OR *\\\\\\\\wceservicepipe*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"17\\" AND winlog.event_data.PipeName.keyword:(*\\\\\\\\lsadump* OR *\\\\\\\\cachedump* OR *\\\\\\\\wceservicepipe*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Cred Dump-Tools Named Pipes\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"17" AND PipeName.keyword:(*\\\\lsadump* *\\\\cachedump* *\\\\wceservicepipe*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="17" (PipeName="*\\\\lsadump*" OR PipeName="*\\\\cachedump*" OR PipeName="*\\\\wceservicepipe*"))
```


### logpoint
    
```
(event_id="17" PipeName IN ["*\\\\lsadump*", "*\\\\cachedump*", "*\\\\wceservicepipe*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*17)(?=.*(?:.*.*\\lsadump.*|.*.*\\cachedump.*|.*.*\\wceservicepipe.*)))'
```



