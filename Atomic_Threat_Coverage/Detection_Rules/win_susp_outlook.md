| Title                    | Suspicious Execution from Outlook       |
|:-------------------------|:------------------|
| **Description**          | Detects EnableUnsafeClientMailRules used for Script Execution from Outlook |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li><li>[T1202: Indirect Command Execution](https://attack.mitre.org/techniques/T1202)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1202: Indirect Command Execution](../Triggers/T1202.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/sensepost/ruler](https://github.com/sensepost/ruler)</li><li>[https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html](https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html)</li></ul>  |
| **Author**               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Suspicious Execution from Outlook
id: e212d415-0e93-435f-9e1a-f29005bb4723
status: experimental
description: Detects EnableUnsafeClientMailRules used for Script Execution from Outlook
references:
    - https://github.com/sensepost/ruler
    - https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html
tags:
    - attack.execution
    - attack.t1059
    - attack.t1202
author: Markus Neis
date: 2018/12/27
logsource:
    category: process_creation
    product: windows
detection:
    clientMailRules:
        CommandLine: '*EnableUnsafeClientMailRules*'
    outlookExec:
        ParentImage: '*\outlook.exe'
        CommandLine: \\\\*\\*.exe
    condition: clientMailRules or outlookExec
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*EnableUnsafeClientMailRules.*" -or ($_.message -match "ParentImage.*.*\\\\outlook.exe" -and $_.message -match "CommandLine.*\\\\\\\\.*\\\\.*.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*EnableUnsafeClientMailRules* OR (winlog.event_data.ParentImage.keyword:*\\\\outlook.exe AND winlog.event_data.CommandLine.keyword:\\\\\\\\*\\\\*.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/e212d415-0e93-435f-9e1a-f29005bb4723 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Execution from Outlook",\n    "description": "Detects EnableUnsafeClientMailRules used for Script Execution from Outlook",\n    "tags": [\n      "attack.execution",\n      "attack.t1059",\n      "attack.t1202"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:*EnableUnsafeClientMailRules* OR (winlog.event_data.ParentImage.keyword:*\\\\\\\\outlook.exe AND winlog.event_data.CommandLine.keyword:\\\\\\\\\\\\\\\\*\\\\\\\\*.exe))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:*EnableUnsafeClientMailRules* OR (winlog.event_data.ParentImage.keyword:*\\\\\\\\outlook.exe AND winlog.event_data.CommandLine.keyword:\\\\\\\\\\\\\\\\*\\\\\\\\*.exe))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Execution from Outlook\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:*EnableUnsafeClientMailRules* OR (ParentImage.keyword:*\\\\outlook.exe AND CommandLine.keyword:\\\\\\\\*\\\\*.exe))
```


### splunk
    
```
(CommandLine="*EnableUnsafeClientMailRules*" OR (ParentImage="*\\\\outlook.exe" CommandLine="\\\\\\\\*\\\\*.exe"))
```


### logpoint
    
```
(CommandLine="*EnableUnsafeClientMailRules*" OR (ParentImage="*\\\\outlook.exe" CommandLine="\\\\\\\\*\\\\*.exe"))
```


### grep
    
```
grep -P '^(?:.*(?:.*.*EnableUnsafeClientMailRules.*|.*(?:.*(?=.*.*\\outlook\\.exe)(?=.*\\\\\\\\.*\\\\.*\\.exe))))'
```



