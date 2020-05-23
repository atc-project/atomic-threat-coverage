| Title                    | Encoded IEX       |
|:-------------------------|:------------------|
| **Description**          | Detects a base64 encoded IEX command string in a process command line |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Encoded IEX
id: 88f680b8-070e-402c-ae11-d2914f2257f1
status: experimental
description: Detects a base64 encoded IEX command string in a process command line
author: Florian Roth
date: 2019/08/23
tags:
    - attack.t1086
    - attack.t1140
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|base64offset|contains: 
          - 'IEX (['
          - 'iex (['
          - 'iex (New'
          - 'IEX (New'
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
Get-WinEvent | where {($_.message -match "CommandLine.*.*SUVYIChb.*" -or $_.message -match "CommandLine.*.*lFWCAoW.*" -or $_.message -match "CommandLine.*.*JRVggKF.*" -or $_.message -match "CommandLine.*.*aWV4IChb.*" -or $_.message -match "CommandLine.*.*lleCAoW.*" -or $_.message -match "CommandLine.*.*pZXggKF.*" -or $_.message -match "CommandLine.*.*aWV4IChOZX.*" -or $_.message -match "CommandLine.*.*lleCAoTmV3.*" -or $_.message -match "CommandLine.*.*pZXggKE5ld.*" -or $_.message -match "CommandLine.*.*SUVYIChOZX.*" -or $_.message -match "CommandLine.*.*lFWCAoTmV3.*" -or $_.message -match "CommandLine.*.*JRVggKE5ld.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*SUVYIChb* OR *lFWCAoW* OR *JRVggKF* OR *aWV4IChb* OR *lleCAoW* OR *pZXggKF* OR *aWV4IChOZX* OR *lleCAoTmV3* OR *pZXggKE5ld* OR *SUVYIChOZX* OR *lFWCAoTmV3* OR *JRVggKE5ld*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/88f680b8-070e-402c-ae11-d2914f2257f1 <<EOF\n{\n  "metadata": {\n    "title": "Encoded IEX",\n    "description": "Detects a base64 encoded IEX command string in a process command line",\n    "tags": [\n      "attack.t1086",\n      "attack.t1140",\n      "attack.execution"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(*SUVYIChb* OR *lFWCAoW* OR *JRVggKF* OR *aWV4IChb* OR *lleCAoW* OR *pZXggKF* OR *aWV4IChOZX* OR *lleCAoTmV3* OR *pZXggKE5ld* OR *SUVYIChOZX* OR *lFWCAoTmV3* OR *JRVggKE5ld*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(*SUVYIChb* OR *lFWCAoW* OR *JRVggKF* OR *aWV4IChb* OR *lleCAoW* OR *pZXggKF* OR *aWV4IChOZX* OR *lleCAoTmV3* OR *pZXggKE5ld* OR *SUVYIChOZX* OR *lFWCAoTmV3* OR *JRVggKE5ld*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Encoded IEX\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(*SUVYIChb* *lFWCAoW* *JRVggKF* *aWV4IChb* *lleCAoW* *pZXggKF* *aWV4IChOZX* *lleCAoTmV3* *pZXggKE5ld* *SUVYIChOZX* *lFWCAoTmV3* *JRVggKE5ld*)
```


### splunk
    
```
(CommandLine="*SUVYIChb*" OR CommandLine="*lFWCAoW*" OR CommandLine="*JRVggKF*" OR CommandLine="*aWV4IChb*" OR CommandLine="*lleCAoW*" OR CommandLine="*pZXggKF*" OR CommandLine="*aWV4IChOZX*" OR CommandLine="*lleCAoTmV3*" OR CommandLine="*pZXggKE5ld*" OR CommandLine="*SUVYIChOZX*" OR CommandLine="*lFWCAoTmV3*" OR CommandLine="*JRVggKE5ld*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["*SUVYIChb*", "*lFWCAoW*", "*JRVggKF*", "*aWV4IChb*", "*lleCAoW*", "*pZXggKF*", "*aWV4IChOZX*", "*lleCAoTmV3*", "*pZXggKE5ld*", "*SUVYIChOZX*", "*lFWCAoTmV3*", "*JRVggKE5ld*"]
```


### grep
    
```
grep -P '^(?:.*.*SUVYIChb.*|.*.*lFWCAoW.*|.*.*JRVggKF.*|.*.*aWV4IChb.*|.*.*lleCAoW.*|.*.*pZXggKF.*|.*.*aWV4IChOZX.*|.*.*lleCAoTmV3.*|.*.*pZXggKE5ld.*|.*.*SUVYIChOZX.*|.*.*lFWCAoTmV3.*|.*.*JRVggKE5ld.*)'
```



