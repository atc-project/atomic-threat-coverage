| Title                | Registry Persistence Mechanisms                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects persistence registry keys                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1183: Image File Execution Options Injection](https://attack.mitre.org/techniques/T1183)</li></ul>  |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1183: Image File Execution Options Injection](../Triggers/T1183.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/)</li></ul>  |
| Author               | Karneades |
| Other Tags           | <ul><li>car.2013-01-002</li><li>car.2013-01-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Registry Persistence Mechanisms
description: Detects persistence registry keys 
references:
    - https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
date: 2018/04/11
author: Karneades
logsource:
   product: windows
   service: sysmon
detection:
    selection_reg1:
        EventID: 13 
        TargetObject: 
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\*\GlobalFlag'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\\*\ReportingMode'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\\*\MonitorProcess'
        EventType: 'SetValue'
    condition: selection_reg1
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.defense_evasion
    - attack.t1183
    - car.2013-01-002
falsepositives:
    - unknown
level: critical

```





### es-qs
    
```
(EventID:"13" AND TargetObject.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\*\\\\GlobalFlag *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\ReportingMode *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\MonitorProcess) AND EventType:"SetValue")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Registry-Persistence-Mechanisms <<EOF\n{\n  "metadata": {\n    "title": "Registry Persistence Mechanisms",\n    "description": "Detects persistence registry keys",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.persistence",\n      "attack.defense_evasion",\n      "attack.t1183",\n      "car.2013-01-002"\n    ],\n    "query": "(EventID:\\"13\\" AND TargetObject.keyword:(*\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\*\\\\\\\\GlobalFlag *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\SilentProcessExit\\\\\\\\*\\\\\\\\ReportingMode *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\SilentProcessExit\\\\\\\\*\\\\\\\\MonitorProcess) AND EventType:\\"SetValue\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"13\\" AND TargetObject.keyword:(*\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\*\\\\\\\\GlobalFlag *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\SilentProcessExit\\\\\\\\*\\\\\\\\ReportingMode *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\SilentProcessExit\\\\\\\\*\\\\\\\\MonitorProcess) AND EventType:\\"SetValue\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Registry Persistence Mechanisms\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND TargetObject:("*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\*\\\\GlobalFlag" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\ReportingMode" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\MonitorProcess") AND EventType:"SetValue")
```


### splunk
    
```
(EventID="13" (TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\*\\\\GlobalFlag" OR TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\ReportingMode" OR TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\MonitorProcess") EventType="SetValue")
```


### logpoint
    
```
(EventID="13" TargetObject IN ["*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\*\\\\GlobalFlag", "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\ReportingMode", "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\MonitorProcess"] EventType="SetValue")
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\\\.*\\GlobalFlag|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\\\.*\\ReportingMode|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\\\.*\\MonitorProcess))(?=.*SetValue))'
```



