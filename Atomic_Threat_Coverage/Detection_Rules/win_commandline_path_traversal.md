| Title                    | Cmd.exe CommandLine Path Traversal       |
|:-------------------------|:------------------|
| **Description**          | detects the usage of path traversal in cmd.exe indicating possible command/argument confusion/hijacking |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.003: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003)</li><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.003: Windows Command Shell](../Triggers/T1059.003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>(not much) some benign Java tools may product false-positive commandlines for loading libraries</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/](https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/)</li><li>[https://twitter.com/Oddvarmoe/status/1270633613449723905](https://twitter.com/Oddvarmoe/status/1270633613449723905)</li></ul>  |
| **Author**               | xknow @xknow_infosec |


## Detection Rules

### Sigma rule

```
title: Cmd.exe CommandLine Path Traversal
id: 087790e3-3287-436c-bccf-cbd0184a7db1
description: detects the usage of path traversal in cmd.exe indicating possible command/argument confusion/hijacking
status: experimental
date: 2020/06/11
author: xknow @xknow_infosec
references:
    - https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/
    - https://twitter.com/Oddvarmoe/status/1270633613449723905
tags:
    - attack.execution
    - attack.t1059.003
    - attack.t1059  # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentCommandLine|contains: 'cmd*/c'
        CommandLine|contains: '/../../'
    condition: selection
falsepositives:
    - (not much) some benign Java tools may product false-positive commandlines for loading libraries
level: high
```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ParentCommandLine.*.*cmd.*/c.*" -and $_.message -match "CommandLine.*.*/../../.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentCommandLine.keyword:*cmd*\\/c* AND winlog.event_data.CommandLine.keyword:*\\/..\\/..\\/*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/087790e3-3287-436c-bccf-cbd0184a7db1 <<EOF\n{\n  "metadata": {\n    "title": "Cmd.exe CommandLine Path Traversal",\n    "description": "detects the usage of path traversal in cmd.exe indicating possible command/argument confusion/hijacking",\n    "tags": [\n      "attack.execution",\n      "attack.t1059.003",\n      "attack.t1059"\n    ],\n    "query": "(winlog.event_data.ParentCommandLine.keyword:*cmd*\\\\/c* AND winlog.event_data.CommandLine.keyword:*\\\\/..\\\\/..\\\\/*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.ParentCommandLine.keyword:*cmd*\\\\/c* AND winlog.event_data.CommandLine.keyword:*\\\\/..\\\\/..\\\\/*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Cmd.exe CommandLine Path Traversal\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentCommandLine.keyword:*cmd*\\/c* AND CommandLine.keyword:*\\/..\\/..\\/*)
```


### splunk
    
```
(ParentCommandLine="*cmd*/c*" CommandLine="*/../../*")
```


### logpoint
    
```
(ParentCommandLine="*cmd*/c*" CommandLine="*/../../*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*cmd.*/c.*)(?=.*.*/\\.\\./\\.\\./.*))'
```



