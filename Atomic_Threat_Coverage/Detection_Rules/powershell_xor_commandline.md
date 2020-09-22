| Title                    | Suspicious XOR Encoded PowerShell Command Line       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059.001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0038_400_engine_state_is_changed_from_none_to_available](../Data_Needed/DN_0038_400_engine_state_is_changed_from_none_to_available.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Teymur Kheirkhabarov, Harish Segar (rule) |


## Detection Rules

### Sigma rule

```
title: Suspicious XOR Encoded PowerShell Command Line
id: 812837bb-b17f-45e9-8bd0-0ec35d2e3bd6
description: Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands.
status: experimental
author: Teymur Kheirkhabarov, Harish Segar (rule)
date: 2020/06/29
tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1086  #an old one
logsource:
  product: windows
  service: powershell-classic
detection:
  selection:
    EventID: 400
    HostName: "ConsoleHost"
  filter:
    CommandLine|contains:
      - "bxor"
      - "join"
      - "char"
  condition: selection and filter
falsepositives:
  - unknown
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Windows PowerShell | where {($_.ID -eq "400" -and $_.message -match "HostName.*ConsoleHost" -and ($_.message -match "CommandLine.*.*bxor.*" -or $_.message -match "CommandLine.*.*join.*" -or $_.message -match "CommandLine.*.*char.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"400" AND HostName:"ConsoleHost" AND winlog.event_data.CommandLine.keyword:(*bxor* OR *join* OR *char*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/812837bb-b17f-45e9-8bd0-0ec35d2e3bd6 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious XOR Encoded PowerShell Command Line",\n    "description": "Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands.",\n    "tags": [\n      "attack.execution",\n      "attack.t1059.001",\n      "attack.t1086"\n    ],\n    "query": "(winlog.event_id:\\"400\\" AND HostName:\\"ConsoleHost\\" AND winlog.event_data.CommandLine.keyword:(*bxor* OR *join* OR *char*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_id:\\"400\\" AND HostName:\\"ConsoleHost\\" AND winlog.event_data.CommandLine.keyword:(*bxor* OR *join* OR *char*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious XOR Encoded PowerShell Command Line\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"400" AND HostName:"ConsoleHost" AND CommandLine.keyword:(*bxor* *join* *char*))
```


### splunk
    
```
(source="Windows PowerShell" EventCode="400" HostName="ConsoleHost" (CommandLine="*bxor*" OR CommandLine="*join*" OR CommandLine="*char*"))
```


### logpoint
    
```
(event_id="400" HostName="ConsoleHost" CommandLine IN ["*bxor*", "*join*", "*char*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*400)(?=.*ConsoleHost)(?=.*(?:.*.*bxor.*|.*.*join.*|.*.*char.*)))'
```



