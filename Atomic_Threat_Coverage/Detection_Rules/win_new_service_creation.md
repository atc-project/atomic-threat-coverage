| Title                    | New Service Creation       |
|:-------------------------|:------------------|
| **Description**          | Detects creation if a new service |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1050: New Service](../Triggers/T1050.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Legitimate administrator or user creates a service for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1050/T1050.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1050/T1050.yaml)</li></ul>  |
| **Author**               | Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: New Service Creation
id: 7fe71fc9-de3b-432a-8d57-8c809efc10ab
status: experimental
description: Detects creation if a new service
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
date: 2019/10/21
modified: 2019/11/04
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1050
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1050/T1050.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith: '\sc.exe'
        CommandLine|contains|all:
            - 'create'
            - 'binpath'
      - Image|endswith: '\powershell.exe'
        CommandLine|contains: 'new-service'
    condition: selection
falsepositives:
    - Legitimate administrator or user creates a service for legitimate reason
level: low

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\sc.exe" -and $_.message -match "CommandLine.*.*create.*" -and $_.message -match "CommandLine.*.*binpath.*") -or ($_.message -match "Image.*.*\\\\powershell.exe" -and $_.message -match "CommandLine.*.*new-service.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\\\sc.exe AND winlog.event_data.CommandLine.keyword:*create* AND winlog.event_data.CommandLine.keyword:*binpath*) OR (winlog.event_data.Image.keyword:*\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*new\\-service*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/7fe71fc9-de3b-432a-8d57-8c809efc10ab <<EOF\n{\n  "metadata": {\n    "title": "New Service Creation",\n    "description": "Detects creation if a new service",\n    "tags": [\n      "attack.persistence",\n      "attack.privilege_escalation",\n      "attack.t1050"\n    ],\n    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\sc.exe AND winlog.event_data.CommandLine.keyword:*create* AND winlog.event_data.CommandLine.keyword:*binpath*) OR (winlog.event_data.Image.keyword:*\\\\\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*new\\\\-service*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\sc.exe AND winlog.event_data.CommandLine.keyword:*create* AND winlog.event_data.CommandLine.keyword:*binpath*) OR (winlog.event_data.Image.keyword:*\\\\\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:*new\\\\-service*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'New Service Creation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\sc.exe AND CommandLine.keyword:*create* AND CommandLine.keyword:*binpath*) OR (Image.keyword:*\\\\powershell.exe AND CommandLine.keyword:*new\\-service*))
```


### splunk
    
```
((Image="*\\\\sc.exe" CommandLine="*create*" CommandLine="*binpath*") OR (Image="*\\\\powershell.exe" CommandLine="*new-service*"))
```


### logpoint
    
```
((Image="*\\\\sc.exe" CommandLine="*create*" CommandLine="*binpath*") OR (Image="*\\\\powershell.exe" CommandLine="*new-service*"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\\sc\\.exe)(?=.*.*create.*)(?=.*.*binpath.*))|.*(?:.*(?=.*.*\\powershell\\.exe)(?=.*.*new-service.*))))'
```



