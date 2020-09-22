| Title                    | Encoded FromBase64String       |
|:-------------------------|:------------------|
| **Description**          | Detects a base64 encoded FromBase64String keyword in a process command line |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059.001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Encoded FromBase64String
id: fdb62a13-9a81-4e5c-a38f-ea93a16f6d7c
status: experimental
description: Detects a base64 encoded FromBase64String keyword in a process command line
author: Florian Roth
date: 2019/08/24
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.execution
    - attack.t1059.001
    - attack.t1086  # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|base64offset|contains: '::FromBase64String'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*OjpGcm9tQmFzZTY0U3RyaW5n.*" -or $_.message -match "CommandLine.*.*o6RnJvbUJhc2U2NFN0cmluZ.*" -or $_.message -match "CommandLine.*.*6OkZyb21CYXNlNjRTdHJpbm.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*OjpGcm9tQmFzZTY0U3RyaW5n* OR *o6RnJvbUJhc2U2NFN0cmluZ* OR *6OkZyb21CYXNlNjRTdHJpbm*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/fdb62a13-9a81-4e5c-a38f-ea93a16f6d7c <<EOF\n{\n  "metadata": {\n    "title": "Encoded FromBase64String",\n    "description": "Detects a base64 encoded FromBase64String keyword in a process command line",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1140",\n      "attack.execution",\n      "attack.t1059.001",\n      "attack.t1086"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(*OjpGcm9tQmFzZTY0U3RyaW5n* OR *o6RnJvbUJhc2U2NFN0cmluZ* OR *6OkZyb21CYXNlNjRTdHJpbm*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(*OjpGcm9tQmFzZTY0U3RyaW5n* OR *o6RnJvbUJhc2U2NFN0cmluZ* OR *6OkZyb21CYXNlNjRTdHJpbm*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Encoded FromBase64String\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(*OjpGcm9tQmFzZTY0U3RyaW5n* *o6RnJvbUJhc2U2NFN0cmluZ* *6OkZyb21CYXNlNjRTdHJpbm*)
```


### splunk
    
```
(CommandLine="*OjpGcm9tQmFzZTY0U3RyaW5n*" OR CommandLine="*o6RnJvbUJhc2U2NFN0cmluZ*" OR CommandLine="*6OkZyb21CYXNlNjRTdHJpbm*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["*OjpGcm9tQmFzZTY0U3RyaW5n*", "*o6RnJvbUJhc2U2NFN0cmluZ*", "*6OkZyb21CYXNlNjRTdHJpbm*"]
```


### grep
    
```
grep -P '^(?:.*.*OjpGcm9tQmFzZTY0U3RyaW5n.*|.*.*o6RnJvbUJhc2U2NFN0cmluZ.*|.*.*6OkZyb21CYXNlNjRTdHJpbm.*)'
```



