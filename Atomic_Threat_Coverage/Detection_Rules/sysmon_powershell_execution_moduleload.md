| Title                | PowerShell Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of PowerShell                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/hunters-forge/ThreatHunter-Playbook/blob/8869b7a58dba1cff63bae1d7ab923974b8c0539b/playbooks/WIN-190410151110.yaml](https://github.com/hunters-forge/ThreatHunter-Playbook/blob/8869b7a58dba1cff63bae1d7ab923974b8c0539b/playbooks/WIN-190410151110.yaml)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: PowerShell Execution
id: 867613fb-fa60-4497-a017-a82df74a172c
description: Detects execution of PowerShell
status: experimental
date: 2019/09/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/hunters-forge/ThreatHunter-Playbook/blob/8869b7a58dba1cff63bae1d7ab923974b8c0539b/playbooks/WIN-190410151110.yaml
logsource:
    product: windows
    service: sysmon
tags:
    - attack.execution
    - attack.t1086
detection:
    selection: 
        EventID: 7
        Description: 'system.management.automation'
        ImageLoaded|contains: 'system.management.automation'
    condition: selection
fields:
    - ComputerName
    - Image
    - ProcessID
    - ImageLoaded
falsepositives:
    - Unknown
level: medium

```





### es-qs
    
```
(EventID:"7" AND Description:"system.management.automation" AND ImageLoaded.keyword:*system.management.automation*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/867613fb-fa60-4497-a017-a82df74a172c <<EOF\n{\n  "metadata": {\n    "title": "PowerShell Execution",\n    "description": "Detects execution of PowerShell",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "(EventID:\\"7\\" AND Description:\\"system.management.automation\\" AND ImageLoaded.keyword:*system.management.automation*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"7\\" AND Description:\\"system.management.automation\\" AND ImageLoaded.keyword:*system.management.automation*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PowerShell Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n       Image = {{_source.Image}}\\n   ProcessID = {{_source.ProcessID}}\\n ImageLoaded = {{_source.ImageLoaded}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"7" AND Description:"system.management.automation" AND ImageLoaded.keyword:*system.management.automation*)
```


### splunk
    
```
(EventID="7" Description="system.management.automation" ImageLoaded="*system.management.automation*") | table ComputerName,Image,ProcessID,ImageLoaded
```


### logpoint
    
```
(event_id="7" Description="system.management.automation" ImageLoaded="*system.management.automation*")
```


### grep
    
```
grep -P '^(?:.*(?=.*7)(?=.*system\\.management\\.automation)(?=.*.*system\\.management\\.automation.*))'
```



