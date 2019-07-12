| Title                | PowerShell Download from URL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Powershell process that contains download commands in its command line string                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell Download from URL
status: experimental
description: Detects a Powershell process that contains download commands in its command line string
author: Florian Roth
tags:
    - attack.t1086
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\powershell.exe'
        CommandLine:
            - '*new-object system.net.webclient).downloadstring(*'
            - '*new-object system.net.webclient).downloadfile(*'
            - '*new-object net.webclient).downloadstring(*'
            - '*new-object net.webclient).downloadfile(*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: medium

```





### es-qs
    
```
(Image.keyword:*\\\\powershell.exe AND CommandLine.keyword:(*new\\-object\\ system.net.webclient\\).downloadstring\\(* *new\\-object\\ system.net.webclient\\).downloadfile\\(* *new\\-object\\ net.webclient\\).downloadstring\\(* *new\\-object\\ net.webclient\\).downloadfile\\(*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/PowerShell-Download-from-URL <<EOF\n{\n  "metadata": {\n    "title": "PowerShell Download from URL",\n    "description": "Detects a Powershell process that contains download commands in its command line string",\n    "tags": [\n      "attack.t1086",\n      "attack.execution"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\powershell.exe AND CommandLine.keyword:(*new\\\\-object\\\\ system.net.webclient\\\\).downloadstring\\\\(* *new\\\\-object\\\\ system.net.webclient\\\\).downloadfile\\\\(* *new\\\\-object\\\\ net.webclient\\\\).downloadstring\\\\(* *new\\\\-object\\\\ net.webclient\\\\).downloadfile\\\\(*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\powershell.exe AND CommandLine.keyword:(*new\\\\-object\\\\ system.net.webclient\\\\).downloadstring\\\\(* *new\\\\-object\\\\ system.net.webclient\\\\).downloadfile\\\\(* *new\\\\-object\\\\ net.webclient\\\\).downloadstring\\\\(* *new\\\\-object\\\\ net.webclient\\\\).downloadfile\\\\(*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PowerShell Download from URL\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image:"*\\\\powershell.exe" AND CommandLine:("*new\\-object system.net.webclient\\).downloadstring\\(*" "*new\\-object system.net.webclient\\).downloadfile\\(*" "*new\\-object net.webclient\\).downloadstring\\(*" "*new\\-object net.webclient\\).downloadfile\\(*"))
```


### splunk
    
```
(Image="*\\\\powershell.exe" (CommandLine="*new-object system.net.webclient).downloadstring(*" OR CommandLine="*new-object system.net.webclient).downloadfile(*" OR CommandLine="*new-object net.webclient).downloadstring(*" OR CommandLine="*new-object net.webclient).downloadfile(*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image="*\\\\powershell.exe" CommandLine IN ["*new-object system.net.webclient).downloadstring(*", "*new-object system.net.webclient).downloadfile(*", "*new-object net.webclient).downloadstring(*", "*new-object net.webclient).downloadfile(*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\powershell\\.exe)(?=.*(?:.*.*new-object system\\.net\\.webclient\\)\\.downloadstring\\(.*|.*.*new-object system\\.net\\.webclient\\)\\.downloadfile\\(.*|.*.*new-object net\\.webclient\\)\\.downloadstring\\(.*|.*.*new-object net\\.webclient\\)\\.downloadfile\\(.*)))'
```



