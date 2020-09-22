| Title                    | PowerShell Encoded Character Syntax       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious encoded character syntax often used for defense evasion |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059.001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/0gtweet/status/1281103918693482496](https://twitter.com/0gtweet/status/1281103918693482496)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell Encoded Character Syntax
id: e312efd0-35a1-407f-8439-b8d434b438a6
status: experimental
description: Detects suspicious encoded character syntax often used for defense evasion
references:
    - https://twitter.com/0gtweet/status/1281103918693482496
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086      # an old one
    - attack.defense_evasion
    - attack.t1027
author: Florian Roth
date: 2020/07/09
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '(WCHAR)0x'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.*(WCHAR)0x.*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*\\(WCHAR\\)0x*
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/e312efd0-35a1-407f-8439-b8d434b438a6 <<EOF\n{\n  "metadata": {\n    "title": "PowerShell Encoded Character Syntax",\n    "description": "Detects suspicious encoded character syntax often used for defense evasion",\n    "tags": [\n      "attack.execution",\n      "attack.t1059.001",\n      "attack.t1086",\n      "attack.defense_evasion",\n      "attack.t1027"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:*\\\\(WCHAR\\\\)0x*"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:*\\\\(WCHAR\\\\)0x*",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PowerShell Encoded Character Syntax\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:*\\(WCHAR\\)0x*
```


### splunk
    
```
CommandLine="*(WCHAR)0x*"
```


### logpoint
    
```
CommandLine="*(WCHAR)0x*"
```


### grep
    
```
grep -P '^.*\\(WCHAR\\)0x.*'
```



