| Title                | Suspicious XOR Encoded PowerShell Command Line                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious powershell process which includes bxor command, alternatvide obfuscation method to b64 encoded commands.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Sami Ruohonen |


## Detection Rules

### Sigma rule

```
title: Suspicious XOR Encoded PowerShell Command Line
description: Detects suspicious powershell process which includes bxor command, alternatvide obfuscation method to b64 encoded commands.
status: experimental
author: Sami Ruohonen
date: 2018/09/05
tags:
    - attack.execution
    - attack.t1086
detection:
    selection:
        CommandLine:
            - '* -bxor*'
    condition: selection
falsepositives:
    - unknown
level: medium
logsource:
    category: process_creation
    product: windows

```





### es-qs
    
```
CommandLine.keyword:(*\\ \\-bxor*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-XOR-Encoded-PowerShell-Command-Line <<EOF\n{\n  "metadata": {\n    "title": "Suspicious XOR Encoded PowerShell Command Line",\n    "description": "Detects suspicious powershell process which includes bxor command, alternatvide obfuscation method to b64 encoded commands.",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "CommandLine.keyword:(*\\\\ \\\\-bxor*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(*\\\\ \\\\-bxor*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious XOR Encoded PowerShell Command Line\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("* \\-bxor*")
```


### splunk
    
```
(CommandLine="* -bxor*")
```


### logpoint
    
```
CommandLine IN ["* -bxor*"]
```


### grep
    
```
grep -P '^(?:.*.* -bxor.*)'
```



