| Title                | T1086 PowerShell Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of PowerShell                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/basic_powershell_execution.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/basic_powershell_execution.md)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: T1086 PowerShell Execution
id: 867613fb-fa60-4497-a017-a82df74a172c
description: Detects execution of PowerShell
status: experimental
date: 2019/09/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/basic_powershell_execution.md
logsource:
    product: windows
    service: sysmon
detection:
    selection: 
        EventID: 7
        Description: 'system.management.automation'
        ImageLoaded|contains: 'system.management.automation'
    condition: selection
falsepositives:
    - Unknown
level: critical
```





### es-qs
    
```
(EventID:"7" AND Description:"system.management.automation" AND ImageLoaded.keyword:*system.management.automation*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/T1086-PowerShell-Execution <<EOF\n{\n  "metadata": {\n    "title": "T1086 PowerShell Execution",\n    "description": "Detects execution of PowerShell",\n    "tags": "",\n    "query": "(EventID:\\"7\\" AND Description:\\"system.management.automation\\" AND ImageLoaded.keyword:*system.management.automation*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"7\\" AND Description:\\"system.management.automation\\" AND ImageLoaded.keyword:*system.management.automation*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'T1086 PowerShell Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"7" AND Description:"system.management.automation" AND ImageLoaded.keyword:*system.management.automation*)
```


### splunk
    
```
(EventID="7" Description="system.management.automation" ImageLoaded="*system.management.automation*")
```


### logpoint
    
```
(event_id="7" Description="system.management.automation" ImageLoaded="*system.management.automation*")
```


### grep
    
```
grep -P '^(?:.*(?=.*7)(?=.*system\\.management\\.automation)(?=.*.*system\\.management\\.automation.*))'
```



