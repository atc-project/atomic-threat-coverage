| Title                    | PsExec Tool Execution       |
|:-------------------------|:------------------|
| **Description**          | Detects PsExec service installation and execution events (service and Sysmon) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li><li>[T1569.002: Service Execution](https://attack.mitre.org/techniques/T1569/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li><li>[DN_0031_7036_service_started_stopped](../Data_Needed/DN_0031_7036_service_started_stopped.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1569.002: Service Execution](../Triggers/T1569.002.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.jpcert.or.jp/english/pub/sr/ir_research.html](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)</li><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)</li></ul>  |
| **Author**               | Thomas Patzke |
| Other Tags           | <ul><li>attack.s0029</li></ul> | 

## Detection Rules

### Sigma rule

```
action: global
title: PsExec Tool Execution
id: 42c575ea-e41e-41f1-b248-8093c3e82a28
status: experimental
description: Detects PsExec service installation and execution events (service and Sysmon)
author: Thomas Patzke
date: 2017/06/12
modified: 2020/08/23
references:
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
tags:
    - attack.execution
    - attack.t1035           # an old one
    - attack.t1569.002
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





### powershell
    
```
Get-WinEvent -LogName System | where {($_.message -match "ServiceName.*PSEXESVC" -and (($_.ID -eq "7045" -and $_.message -match "ServiceFileName.*.*\\\\PSEXESVC.exe") -or $_.ID -eq "7036")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message\nGet-WinEvent -LogName System | where {($_.message -match "Image.*.*\\\\PSEXESVC.exe" -and $_.message -match "User.*NT AUTHORITY\\\\SYSTEM") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ServiceName:"PSEXESVC" AND ((winlog.event_id:"7045" AND winlog.event_data.ServiceFileName.keyword:*\\\\PSEXESVC.exe) OR winlog.event_id:"7036"))\n(winlog.event_data.Image.keyword:*\\\\PSEXESVC.exe AND winlog.event_data.User:"NT\\ AUTHORITY\\\\SYSTEM")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/42c575ea-e41e-41f1-b248-8093c3e82a28 <<EOF\n{\n  "metadata": {\n    "title": "PsExec Tool Execution",\n    "description": "Detects PsExec service installation and execution events (service and Sysmon)",\n    "tags": [\n      "attack.execution",\n      "attack.t1035",\n      "attack.t1569.002",\n      "attack.s0029"\n    ],\n    "query": "(winlog.event_data.ServiceName:\\"PSEXESVC\\" AND ((winlog.event_id:\\"7045\\" AND winlog.event_data.ServiceFileName.keyword:*\\\\\\\\PSEXESVC.exe) OR winlog.event_id:\\"7036\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.ServiceName:\\"PSEXESVC\\" AND ((winlog.event_id:\\"7045\\" AND winlog.event_data.ServiceFileName.keyword:*\\\\\\\\PSEXESVC.exe) OR winlog.event_id:\\"7036\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PsExec Tool Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n          EventID = {{_source.EventID}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n      ServiceName = {{_source.ServiceName}}\\n  ServiceFileName = {{_source.ServiceFileName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/42c575ea-e41e-41f1-b248-8093c3e82a28-2 <<EOF\n{\n  "metadata": {\n    "title": "PsExec Tool Execution",\n    "description": "Detects PsExec service installation and execution events (service and Sysmon)",\n    "tags": [\n      "attack.execution",\n      "attack.t1035",\n      "attack.t1569.002",\n      "attack.s0029"\n    ],\n    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\PSEXESVC.exe AND winlog.event_data.User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\PSEXESVC.exe AND winlog.event_data.User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PsExec Tool Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n          EventID = {{_source.EventID}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n      ServiceName = {{_source.ServiceName}}\\n  ServiceFileName = {{_source.ServiceFileName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ServiceName:"PSEXESVC" AND ((EventID:"7045" AND ServiceFileName.keyword:*\\\\PSEXESVC.exe) OR EventID:"7036"))\n(Image.keyword:*\\\\PSEXESVC.exe AND User:"NT AUTHORITY\\\\SYSTEM")
```


### splunk
    
```
(source="WinEventLog:System" ServiceName="PSEXESVC" ((EventCode="7045" ServiceFileName="*\\\\PSEXESVC.exe") OR EventCode="7036")) | table EventCode,CommandLine,ParentCommandLine,ServiceName,ServiceFileName\n(Image="*\\\\PSEXESVC.exe" User="NT AUTHORITY\\\\SYSTEM") | table EventCode,CommandLine,ParentCommandLine,ServiceName,ServiceFileName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" service="PSEXESVC" ((event_id="7045" ServiceFileName="*\\\\PSEXESVC.exe") OR event_id="7036"))\n(Image="*\\\\PSEXESVC.exe" User="NT AUTHORITY\\\\SYSTEM")
```


### grep
    
```
grep -P '^(?:.*(?=.*PSEXESVC)(?=.*(?:.*(?:.*(?:.*(?=.*7045)(?=.*.*\\PSEXESVC\\.exe))|.*7036))))'\ngrep -P '^(?:.*(?=.*.*\\PSEXESVC\\.exe)(?=.*NT AUTHORITY\\SYSTEM))'
```



