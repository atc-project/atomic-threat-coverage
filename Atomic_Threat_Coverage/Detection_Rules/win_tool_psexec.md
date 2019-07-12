| Title                | PsExec Tool Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PsExec service installation and execution events (service and Sysmon)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li></ul>  |
| Data Needed          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0031_7036_service_started_stopped](../Data_Needed/DN_0031_7036_service_started_stopped.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1035: Service Execution](../Triggers/T1035.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.jpcert.or.jp/english/pub/sr/ir_research.html](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)</li><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)</li></ul>  |
| Author               | Thomas Patzke |
| Other Tags           | <ul><li>attack.s0029</li><li>attack.s0029</li></ul> | 

## Detection Rules

### Sigma rule

```
---
action: global
title: PsExec Tool Execution
status: experimental
description: Detects PsExec service installation and execution events (service and Sysmon)
author: Thomas Patzke
references:
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
tags:
    - attack.execution
    - attack.t1035
    - attack.s0029
detection:
    condition: 1 of them
fields:
    - EventID
    - CommandLine
    - ParentCommandLine
    - ServiceName
    - ServiceFileName
falsepositives:
    - unknown
level: low
---
logsource:
    product: windows
    service: system
detection:
    service_installation:
        EventID: 7045
        ServiceName: 'PSEXESVC'
        ServiceFileName: '*\PSEXESVC.exe'
    service_execution:
        EventID: 7036
        ServiceName: 'PSEXESVC'
---
logsource:
    category: process_creation
    product: windows
detection:
    sysmon_processcreation:
        Image: '*\PSEXESVC.exe'
        User: 'NT AUTHORITY\SYSTEM'


```





### es-qs
    
```
(ServiceName:"PSEXESVC" AND ((EventID:"7045" AND ServiceFileName.keyword:*\\\\PSEXESVC.exe) OR EventID:"7036"))\n(Image.keyword:*\\\\PSEXESVC.exe AND User:"NT\\ AUTHORITY\\\\SYSTEM")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/PsExec-Tool-Execution <<EOF\n{\n  "metadata": {\n    "title": "PsExec Tool Execution",\n    "description": "Detects PsExec service installation and execution events (service and Sysmon)",\n    "tags": [\n      "attack.execution",\n      "attack.t1035",\n      "attack.s0029"\n    ],\n    "query": "(ServiceName:\\"PSEXESVC\\" AND ((EventID:\\"7045\\" AND ServiceFileName.keyword:*\\\\\\\\PSEXESVC.exe) OR EventID:\\"7036\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ServiceName:\\"PSEXESVC\\" AND ((EventID:\\"7045\\" AND ServiceFileName.keyword:*\\\\\\\\PSEXESVC.exe) OR EventID:\\"7036\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PsExec Tool Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n          EventID = {{_source.EventID}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n      ServiceName = {{_source.ServiceName}}\\n  ServiceFileName = {{_source.ServiceFileName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/PsExec-Tool-Execution-2 <<EOF\n{\n  "metadata": {\n    "title": "PsExec Tool Execution",\n    "description": "Detects PsExec service installation and execution events (service and Sysmon)",\n    "tags": [\n      "attack.execution",\n      "attack.t1035",\n      "attack.s0029"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\PSEXESVC.exe AND User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\PSEXESVC.exe AND User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PsExec Tool Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n          EventID = {{_source.EventID}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n      ServiceName = {{_source.ServiceName}}\\n  ServiceFileName = {{_source.ServiceFileName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ServiceName:"PSEXESVC" AND ((EventID:"7045" AND ServiceFileName:"*\\\\PSEXESVC.exe") OR EventID:"7036"))\n(Image:"*\\\\PSEXESVC.exe" AND User:"NT AUTHORITY\\\\SYSTEM")
```


### splunk
    
```
(ServiceName="PSEXESVC" ((EventID="7045" ServiceFileName="*\\\\PSEXESVC.exe") OR EventID="7036")) | table EventID,CommandLine,ParentCommandLine,ServiceName,ServiceFileName\n(Image="*\\\\PSEXESVC.exe" User="NT AUTHORITY\\\\SYSTEM") | table EventID,CommandLine,ParentCommandLine,ServiceName,ServiceFileName
```


### logpoint
    
```
(ServiceName="PSEXESVC" ((EventID="7045" ServiceFileName="*\\\\PSEXESVC.exe") OR EventID="7036"))\n(Image="*\\\\PSEXESVC.exe" User="NT AUTHORITY\\\\SYSTEM")
```


### grep
    
```
grep -P '^(?:.*(?=.*PSEXESVC)(?=.*(?:.*(?:.*(?:.*(?=.*7045)(?=.*.*\\PSEXESVC\\.exe))|.*7036))))'\ngrep -P '^(?:.*(?=.*.*\\PSEXESVC\\.exe)(?=.*NT AUTHORITY\\SYSTEM))'
```



