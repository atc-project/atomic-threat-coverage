| Title                | PsExec Tool Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PsExec service installation and execution events (service and Sysmon)                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[T1035: Service Execution](../Triggers/T1035.md)</li></ul>  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.jpcert.or.jp/english/pub/sr/ir_research.html](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)</li><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)</li></ul>                                                          |
| Author               | Thomas Patzke                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0029</li><li>attack.s0029</li></ul> | 

## Detection Rules

### Sigma rule

```
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
logsource:
    product: windows
detection:
    service_installation:
        EventID: 7045
        ServiceName: 'PSEXESVC'
        ServiceFileName: '*\PSEXESVC.exe'
    service_execution:
        EventID: 7036
        ServiceName: 'PSEXESVC'
    sysmon_processcreation:
        EventID: 1
        Image: '*\PSEXESVC.exe'
        User: 'NT AUTHORITY\SYSTEM'
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

```




### es-qs
    
```
((EventID:"7045" AND ServiceName:"PSEXESVC" AND ServiceFileName.keyword:*\\\\PSEXESVC.exe) OR (EventID:"7036" AND ServiceName:"PSEXESVC") OR (EventID:"1" AND Image.keyword:*\\\\PSEXESVC.exe AND User:"NT\\ AUTHORITY\\\\SYSTEM"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/PsExec-Tool-Execution <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"7045\\" AND ServiceName:\\"PSEXESVC\\" AND ServiceFileName.keyword:*\\\\\\\\PSEXESVC.exe) OR (EventID:\\"7036\\" AND ServiceName:\\"PSEXESVC\\") OR (EventID:\\"1\\" AND Image.keyword:*\\\\\\\\PSEXESVC.exe AND User:\\"NT\\\\ AUTHORITY\\\\\\\\SYSTEM\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'PsExec Tool Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n          EventID = {{_source.EventID}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n      ServiceName = {{_source.ServiceName}}\\n  ServiceFileName = {{_source.ServiceFileName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"7045" AND ServiceName:"PSEXESVC" AND ServiceFileName:"*\\\\PSEXESVC.exe") OR (EventID:"7036" AND ServiceName:"PSEXESVC") OR (EventID:"1" AND Image:"*\\\\PSEXESVC.exe" AND User:"NT AUTHORITY\\\\SYSTEM"))
```


### splunk
    
```
((EventID="7045" ServiceName="PSEXESVC" ServiceFileName="*\\\\PSEXESVC.exe") OR (EventID="7036" ServiceName="PSEXESVC") OR (EventID="1" Image="*\\\\PSEXESVC.exe" User="NT AUTHORITY\\\\SYSTEM")) | table EventID,CommandLine,ParentCommandLine,ServiceName,ServiceFileName
```


### logpoint
    
```
((EventID="7045" ServiceName="PSEXESVC" ServiceFileName="*\\\\PSEXESVC.exe") OR (EventID="7036" ServiceName="PSEXESVC") OR (EventID="1" Image="*\\\\PSEXESVC.exe" User="NT AUTHORITY\\\\SYSTEM"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*7045)(?=.*PSEXESVC)(?=.*.*\\PSEXESVC\\.exe))|.*(?:.*(?=.*7036)(?=.*PSEXESVC))|.*(?:.*(?=.*1)(?=.*.*\\PSEXESVC\\.exe)(?=.*NT AUTHORITY\\SYSTEM))))'
```


