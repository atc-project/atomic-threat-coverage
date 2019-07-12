| Title                | Microsoft Workflow Compiler                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1127: Trusted Developer Utilities](https://attack.mitre.org/techniques/T1127)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1127: Trusted Developer Utilities](../Triggers/T1127.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Legitimate MWC use (unlikely in modern enterprise environments)</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb](https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb)</li></ul>  |
| Author               | Nik Seetharaman |


## Detection Rules

### Sigma rule

```
title: Microsoft Workflow Compiler
status: experimental
description: Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1127
author: Nik Seetharaman
references:
    - https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\Microsoft.Workflow.Compiler.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate MWC use (unlikely in modern enterprise environments)
level: high

```





### es-qs
    
```
Image.keyword:*\\\\Microsoft.Workflow.Compiler.exe
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Microsoft-Workflow-Compiler <<EOF\n{\n  "metadata": {\n    "title": "Microsoft Workflow Compiler",\n    "description": "Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1127"\n    ],\n    "query": "Image.keyword:*\\\\\\\\Microsoft.Workflow.Compiler.exe"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "Image.keyword:*\\\\\\\\Microsoft.Workflow.Compiler.exe",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Microsoft Workflow Compiler\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Image:"*\\\\Microsoft.Workflow.Compiler.exe"
```


### splunk
    
```
Image="*\\\\Microsoft.Workflow.Compiler.exe" | table CommandLine,ParentCommandLine
```


### logpoint
    
```
Image="*\\\\Microsoft.Workflow.Compiler.exe"
```


### grep
    
```
grep -P '^.*\\Microsoft\\.Workflow\\.Compiler\\.exe'
```



